import React, { useEffect, useRef } from 'react'

const WHITE = '242, 251, 255'
const CYAN = '130, 223, 255'
// The dark palette is intentionally bright, while light backgrounds need
// darker blue-gray stars to retain contrast (the white dark-theme stars would
// disappear against the light canvas).
const LIGHT_WHITE = '62, 104, 140'
const LIGHT_CYAN = '22, 133, 178'
const MIN_ORBIT_SPEED = 0.08
const MAX_ORBIT_SPEED = 0.24

const lerp = (start, end, amount) => start + (end - start) * amount

function createGlowSprite(rgb) {
  const sprite = document.createElement('canvas')
  const size = 64
  const radius = size / 2
  sprite.width = size
  sprite.height = size
  const context = sprite.getContext('2d')
  const gradient = context.createRadialGradient(radius, radius, 0, radius, radius, radius)
  gradient.addColorStop(0, `rgba(${rgb}, 1)`)
  gradient.addColorStop(0.18, `rgba(${rgb}, 0.94)`)
  gradient.addColorStop(0.42, `rgba(${rgb}, 0.48)`)
  gradient.addColorStop(0.72, `rgba(${rgb}, 0.12)`)
  gradient.addColorStop(1, `rgba(${rgb}, 0)`)
  context.fillStyle = gradient
  context.fillRect(0, 0, size, size)
  return sprite
}

function seededRandom(seed) {
  let state = seed >>> 0
  return () => {
    state += 0x6d2b79f5
    let value = state
    value = Math.imul(value ^ (value >>> 15), value | 1)
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61)
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296
  }
}

function starCountFor(width) {
  if (width <= 430) return 92
  if (width <= 744) return 132
  if (width <= 1180) return 178
  return 220
}

export function ControlStarfield() {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return undefined

    const context = canvas.getContext('2d')
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)')
    const palettes = {
      dark: { white: WHITE, cyan: CYAN },
      light: { white: LIGHT_WHITE, cyan: LIGHT_CYAN },
    }
    const glowSprites = {
      dark: { white: createGlowSprite(WHITE), cyan: createGlowSprite(CYAN) },
      light: { white: createGlowSprite(LIGHT_WHITE), cyan: createGlowSprite(LIGHT_CYAN) },
    }
    const pointer = {
      active: false,
      targetX: 0,
      targetY: 0,
      x: 0,
      y: 0,
    }
    let width = 0
    let height = 0
    let stars = []
    let animationId = 0
    let lastTime = 0
    let isVisible = !document.hidden

    const buildStars = () => {
      const random = seededRandom((width * 73856093) ^ (height * 19349663))
      const count = starCountFor(width)

      stars = Array.from({ length: count }, () => {
        const depth = random()
        const orbit = lerp(0.08, 0.58, Math.pow(random(), 0.7))
        return {
          angle: random() * Math.PI * 2,
          color: random() < 0.24 ? 'cyan' : 'white',
          depth,
          orbitRadiusX: width * orbit,
          orbitRadiusY: height * orbit * lerp(0.76, 1.08, random()),
          orbitSpeed: lerp(MIN_ORBIT_SPEED, MAX_ORBIT_SPEED, random()),
          pulsePhase: random() * Math.PI * 2,
          pulseSpeed: lerp(1.8, 5.2, random()),
          size: lerp(0.82, 1.5, random()) * lerp(0.78, 1.2, depth),
          sparkle: random() > 0.94,
        }
      })
    }

    const resize = () => {
      width = canvas.clientWidth
      height = canvas.clientHeight
      const pixelRatio = Math.min(window.devicePixelRatio || 1, 2)
      canvas.width = Math.max(1, Math.floor(width * pixelRatio))
      canvas.height = Math.max(1, Math.floor(height * pixelRatio))
      context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0)
      buildStars()
    }

    const draw = (time, staticFrame = false) => {
      const elapsed = staticFrame ? 0 : time * 0.001
      const centerX = width * 0.56
      const centerY = height * 0.5
      context.clearRect(0, 0, width, height)
      context.save()
      context.globalCompositeOperation = 'lighter'

      pointer.x = lerp(pointer.x, pointer.active ? pointer.targetX : 0, 0.035)
      pointer.y = lerp(pointer.y, pointer.active ? pointer.targetY : 0, 0.035)

      const paletteName = document.body.classList.contains('light-theme') ? 'light' : 'dark'
      const palette = palettes[paletteName]
      stars.forEach((star) => {
        const angle = star.angle - elapsed * star.orbitSpeed
        const parallax = lerp(3, 16, star.depth)
        const x = centerX + Math.cos(angle) * star.orbitRadiusX + pointer.x * parallax
        const y = centerY + Math.sin(angle) * star.orbitRadiusY + pointer.y * parallax
        if (x < -30 || x > width + 30 || y < -30 || y > height + 30) return

        const pulse = staticFrame
          ? 0.62
          : 0.5 + 0.5 * Math.sin(elapsed * star.pulseSpeed + star.pulsePhase)
        const brightness = lerp(0.32, 1, pulse)
        const coreSize = star.size * lerp(0.86, 1.3, brightness)
        const haloSize = coreSize * lerp(7.5, 11, star.depth)
        const rgb = star.color === 'cyan' ? palette.cyan : palette.white

        context.globalAlpha = brightness * lerp(0.48, 0.78, star.depth)
        context.drawImage(
          glowSprites[paletteName][star.color],
          x - haloSize / 2,
          y - haloSize / 2,
          haloSize,
          haloSize,
        )
        context.globalAlpha = brightness * lerp(0.72, 1, star.depth)
        context.fillStyle = `rgb(${rgb})`
        context.beginPath()
        context.arc(x, y, coreSize, 0, Math.PI * 2)
        context.fill()

        if (star.sparkle && brightness > 0.7) {
          const ray = coreSize * 4.5
          context.globalAlpha = (brightness - 0.7) * 0.72
          context.strokeStyle = `rgb(${rgb})`
          context.lineWidth = 0.55
          context.beginPath()
          context.moveTo(x - ray, y)
          context.lineTo(x + ray, y)
          context.moveTo(x, y - ray)
          context.lineTo(x, y + ray)
          context.stroke()
        }
      })

      context.restore()
    }

    const animate = (time) => {
      if (!isVisible || reduceMotion.matches) return
      if (!lastTime || time - lastTime >= (width <= 744 ? 32 : 16)) {
        draw(time)
        lastTime = time
      }
      animationId = window.requestAnimationFrame(animate)
    }

    const restart = () => {
      window.cancelAnimationFrame(animationId)
      lastTime = 0
      resize()
      draw(0, true)
      if (isVisible && !reduceMotion.matches) {
        animationId = window.requestAnimationFrame(animate)
      }
    }

    const handlePointerMove = (event) => {
      pointer.targetX = event.clientX / Math.max(width, 1) - 0.5
      pointer.targetY = event.clientY / Math.max(height, 1) - 0.5
      pointer.active = true
    }

    const handlePointerOut = (event) => {
      if (!event.relatedTarget) pointer.active = false
    }

    const handleVisibility = () => {
      isVisible = !document.hidden
      restart()
    }

    const resizeObserver = new ResizeObserver(restart)
    resizeObserver.observe(canvas)
    reduceMotion.addEventListener('change', restart)
    document.addEventListener('visibilitychange', handleVisibility)
    window.addEventListener('pointermove', handlePointerMove, { passive: true })
    window.addEventListener('pointerout', handlePointerOut)
    restart()

    return () => {
      window.cancelAnimationFrame(animationId)
      resizeObserver.disconnect()
      reduceMotion.removeEventListener('change', restart)
      document.removeEventListener('visibilitychange', handleVisibility)
      window.removeEventListener('pointermove', handlePointerMove)
      window.removeEventListener('pointerout', handlePointerOut)
    }
  }, [])

  return <canvas ref={canvasRef} className="control-starfield" aria-hidden="true" />
}
