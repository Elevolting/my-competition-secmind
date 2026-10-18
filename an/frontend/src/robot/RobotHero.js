import * as THREE from 'three'
import gsap from 'gsap'
import { GLTFLoader } from 'three/examples/jsm/loaders/GLTFLoader.js'
import { DRACOLoader } from 'three/examples/jsm/loaders/DRACOLoader.js'
import { OrbitParticles } from './OrbitParticles.js'
import { FeatureParticle } from './FeatureParticle.js'
import { ParticleExplosion } from './ParticleExplosion.js'

const DEFAULT_PARTICLE_SIZE = 22
const FEATURE_PARTICLE_SIZE = 44

const BLOCKED_SPHERICAL_ARCS = {
  1: [
    { id: 1, start: 75.369406588, end: 169.077120546 },
    { id: 2, start: -105.980430769, end: -76.224797368 },
  ],
  2: [
    { id: 1, start: 10.922879454, end: 104.630593412 },
    { id: 2, start: -103.775202632, end: -74.019569231 },
  ],
}
// Supplemental shoulder-local arc reconstructed from exported records #7-#13.
const SUPPLEMENTAL_BLOCKED_ARC_POINTS = [
  [0.350253399, -0.936654983, 0],
  [0.396010515, -0.918245976, 0],
  [0.448484916, -0.8937904, 0],
  [0.477734426, -0.878504308, 0],
  [0.49913004, -0.866527093, 0],
  [0.527708, -0.842421, 0.108862875],
  [0.527717, -0.783405, 0.328315967],
  [0.541135, -0.66569, 0.513838239],
]
const ADDITIONAL_BLOCKED_ARC_POINTS = [
  [-0.304915771, -0.952379322, 0],
  [-0.291362662, -0.956612669, 0],
  [0.293686389, -0.955901828, 0],
]
const BLOCKED_ARC_TOLERANCE = THREE.MathUtils.degToRad(2)

export class RobotHero {
  constructor(stage, loading, coordinateUi, particleUi, transitionUi, statusBubbleRef = null) {
    this.stage = stage
    this.loading = loading
    this.coordinateUi = coordinateUi
    this.particleUi = particleUi
    this.transitionUi = transitionUi
    this.statusBubbleRef = statusBubbleRef
    this.statusHeadBounds = new THREE.Box3()
    this.statusHeadCorner = new THREE.Vector3()
    this.scene = null
    this.camera = null
    this.renderer = null
    this.model = null
    this.head = null
    this.body = null
    this.arms = []
    this.raycaster = new THREE.Raycaster()
    this.pointer = new THREE.Vector2()
    this.reachTimeline = null
    this.targetMarker = null
    this.orbitParticles = null
    this.featureParticle = null
    this.particleExplosion = null
    this.isReaching = false
    this.interactionState = 'orbiting'
    this.motionTime = 0
    this.lastFrameTime = null
    this.navigationTimer = null
    this.frameId = null
    this.targetRotation = { headX: 0, headY: 0, bodyX: 0, bodyY: 0 }
    this.lerpFactor = 0.05
    this.coordinateStorageKey = 'aula-robot-click-records-v1'
    this.coordinateRecords = this.loadCoordinateRecords()
    this.clearConfirmationTimer = null
    this.particleStorageKey = 'aula-particle-size-v1'
    this.particleSize = this.loadParticleSize()

    this.animate = this.animate.bind(this)
    this.handleResize = this.handleResize.bind(this)
    this.handleMouseMove = this.handleMouseMove.bind(this)
    this.handleSamplingPointerMove = this.handleSamplingPointerMove.bind(this)
    this.handlePointerDown = this.handlePointerDown.bind(this)
    this.hideCoordinateTooltip = this.hideCoordinateTooltip.bind(this)
    this.updateFeatureLabel = this.updateFeatureLabel.bind(this)
  }

  async init() {
    this.scene = new THREE.Scene()
    this.camera = new THREE.PerspectiveCamera(30, 1, 0.1, 2000)
    this.camera.position.set(0, 0, 13)
    this.camera.lookAt(0, 0, 0)

    this.renderer = new THREE.WebGLRenderer({
      alpha: true,
      antialias: true,
      depth: true,
      premultipliedAlpha: true,
      preserveDrawingBuffer: true,
    })
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2))
    this.renderer.outputColorSpace = THREE.SRGBColorSpace
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping
    this.renderer.toneMappingExposure = 1
    this.stage.appendChild(this.renderer.domElement)

    this.handleResize()
    this.addLights()
    await Promise.all([this.loadEnvironment(), this.loadRobot()])

    this.hideLoading()
    this.startIntro()
    window.addEventListener('resize', this.handleResize)
    window.addEventListener('mousemove', this.handleMouseMove)
    this.renderer.domElement.addEventListener('pointermove', this.handleSamplingPointerMove)
    this.renderer.domElement.addEventListener('pointerdown', this.handlePointerDown)
    this.renderer.domElement.addEventListener('pointerleave', this.hideCoordinateTooltip)
    this.setupCoordinateUi()
    this.setupParticleUi()
    this.animate()
  }

  addLights() {
    const rim = new THREE.DirectionalLight(0xffffff, 1.45)
    rim.position.set(0, 0.3, 2)
    this.scene.add(rim)

    const softFill = new THREE.HemisphereLight(0xffffff, 0x111111, 0.35)
    this.scene.add(softFill)
  }

  loadEnvironment() {
    return new Promise((resolve) => {
      new THREE.TextureLoader().load(
        '/model/env.jpg',
        (texture) => {
          texture.mapping = THREE.EquirectangularReflectionMapping
          texture.colorSpace = THREE.SRGBColorSpace
          this.scene.environment = texture
          resolve()
        },
        undefined,
        () => resolve(),
      )
    })
  }

  loadRobot() {
    return new Promise((resolve, reject) => {
      const draco = new DRACOLoader()
      draco.setDecoderPath('/draco/')
      draco.setDecoderConfig({ type: 'wasm' })
      draco.preload()

      const loader = new GLTFLoader()
      loader.setDRACOLoader(draco)
      loader.load(
        '/model/machine-draco.glb',
        (gltf) => {
          this.model = gltf.scene
          this.body = this.findNode(this.model, 'Top_part')

          this.model.traverse((node) => {
            if (node.name === 'Head') this.head = node

            if (node.name === 'Head_2') {
              node.material = new THREE.MeshPhysicalMaterial({
                color: 0x000000,
                metalness: 1,
                roughness: 0.04,
                clearcoat: 1,
                clearcoatRoughness: 0.04,
              })
            }

            if (node.isMesh) {
              node.frustumCulled = false
              node.material.needsUpdate = true
            }
          })

          this.scene.add(this.model)
          this.applyResponsiveLayout()
          this.setupArms()
          this.createOrbitParticles()
          this.createTargetMarker()
          draco.dispose()
          resolve()
        },
        (event) => {
          if (!event.lengthComputable || !this.loading) return
          const percent = Math.round((event.loaded / event.total) * 100)
          this.loading.textContent = `Loading 3D model ${percent}%`
        },
        (error) => {
          draco.dispose()
          reject(error)
        },
      )
    })
  }

  startIntro() {
    const targetZ = this.getTargetCameraZ()
    this.camera.position.z = targetZ + 3.5

    gsap.fromTo(
      this.camera.position,
      { x: 0, y: 0, z: targetZ + 3.5 },
      {
        x: 0,
        y: 0,
        z: targetZ,
        duration: 2,
        ease: 'power3.inOut',
        delay: 0.5,
        onUpdate: () => this.camera.updateProjectionMatrix(),
      },
    )
  }

  animate() {
    this.frameId = requestAnimationFrame(this.animate)
    const now = performance.now() * 0.001
    const deltaTime = this.lastFrameTime === null
      ? 0
      : Math.min(now - this.lastFrameTime, 0.05)
    this.lastFrameTime = now

    if (this.head && this.body) {
      this.head.rotation.x = THREE.MathUtils.lerp(
        this.head.rotation.x,
        this.targetRotation.headX,
        this.lerpFactor,
      )
      this.head.rotation.y = THREE.MathUtils.lerp(
        this.head.rotation.y,
        this.targetRotation.headY,
        this.lerpFactor,
      )
      if (!this.isReaching) {
        this.body.rotation.x = THREE.MathUtils.lerp(
          this.body.rotation.x,
          this.targetRotation.bodyX,
          this.lerpFactor,
        )
        this.body.rotation.y = THREE.MathUtils.lerp(
          this.body.rotation.y,
          this.targetRotation.bodyY,
          this.lerpFactor,
        )
      }
    }

    if (this.interactionState === 'orbiting') {
      this.motionTime += deltaTime
    }

    if (this.orbitParticles) {
      this.orbitParticles.update(this.motionTime)
    }
    if (this.featureParticle) {
      this.featureParticle.update(this.motionTime)
      this.updateFeatureLabel()
    }
    this.updateStatusBubblePosition()
    if (this.particleExplosion && !this.particleExplosion.update(deltaTime)) {
      this.particleExplosion.removeFromParent()
      this.particleExplosion.geometry.dispose()
      this.particleExplosion.material.dispose()
      this.particleExplosion = null
    }

    this.renderer.render(this.scene, this.camera)
  }

  handleResize() {
    const rect = this.stage.getBoundingClientRect()
    const width = Math.max(rect.width, 1)
    const height = Math.max(rect.height, 1)

    this.camera.aspect = width / height
    this.camera.updateProjectionMatrix()
    this.renderer.setSize(width, height, false)
    const pixelRatio = Math.min(window.devicePixelRatio || 1, 2)
    this.orbitParticles?.setPixelRatio(pixelRatio)
    this.featureParticle?.setPixelRatio(pixelRatio)
    this.particleExplosion?.setPixelRatio(pixelRatio)
    this.applyResponsiveLayout()
  }

  getTargetCameraZ() {
    if (!this.camera) return 9.5
    if (this.camera.aspect < 0.7) return 12.5
    if (this.camera.aspect < 1) return 11
    return 9.5
  }

  applyResponsiveLayout() {
    if (!this.camera) return

    const compact = this.camera.aspect < 0.7

    if (this.model) {
      // Keep the robot as a background identity without letting it compete
      // with the cockpit's data panels on desktop screens. Narrow layouts
      // retain the existing compact scale to preserve the mobile composition.
      const scale = compact ? 0.78 : 0.98
      this.model.scale.set(scale, scale, scale)
      this.model.position.set(0, compact ? -1.55 : -1.65, 0)
      this.model.updateMatrixWorld(true)
    }

  }

  handleMouseMove(event) {
    const head = this.getMouseDegrees(event.clientX, event.clientY, 30)
    this.targetRotation.headX = THREE.MathUtils.degToRad(head.y)
    this.targetRotation.headY = THREE.MathUtils.degToRad(head.x)

    const body = this.getMouseDegrees(event.clientX, event.clientY, 10)
    this.targetRotation.bodyX = THREE.MathUtils.degToRad(body.y)
    this.targetRotation.bodyY = THREE.MathUtils.degToRad(body.x)
  }

  handleSamplingPointerMove(event) {
    const sample = this.getPointerSample(event.clientX, event.clientY)
    if (!sample) {
      this.hideCoordinateTooltip()
      return
    }

    this.renderCoordinateTooltip(sample, event.clientX, event.clientY)
  }

  getPointerSample(clientX, clientY) {
    if (this.arms.length !== 2 || !this.model) return null

    const rect = this.renderer.domElement.getBoundingClientRect()
    if (rect.width <= 0 || rect.height <= 0) return null

    this.pointer.set(
      ((clientX - rect.left) / rect.width) * 2 - 1,
      -((clientY - rect.top) / rect.height) * 2 + 1,
    )
    this.raycaster.setFromCamera(this.pointer, this.camera)
    this.model.updateMatrixWorld(true)

    const arm = this.selectArmForPointer(this.pointer.x)
    const orderedArms = this.getScreenOrderedArms()
    const armNumber = orderedArms.indexOf(arm) + 1
    const shoulderWorld = arm.shoulder.getWorldPosition(new THREE.Vector3())
    const frontNormal = this.getFrontNormal(shoulderWorld)
    const shoulderPlane = new THREE.Plane().setFromNormalAndCoplanarPoint(
      frontNormal,
      shoulderWorld,
    )
    const cursorOnPlane = this.raycaster.ray.intersectPlane(
      shoulderPlane,
      new THREE.Vector3(),
    )
    if (!cursorOnPlane) return null

    const rightAxis = new THREE.Vector3(1, 0, 0).transformDirection(this.body.matrixWorld)
    const upAxis = new THREE.Vector3(0, 1, 0).transformDirection(this.body.matrixWorld)
    const planarOffset = cursorOnPlane.clone().sub(shoulderWorld)
    const u = planarOffset.dot(rightAxis) / arm.reach
    const v = planarOffset.dot(upAxis) / arm.reach
    const radius = planarOffset.length() / arm.reach
    const targetWorld = this.getReachTarget(shoulderWorld, arm.reach)
    const blockedArc = this.getBlockedSphericalArc({
      armNumber,
      shoulderWorld,
      targetWorld,
      rightAxis,
      upAxis,
      frontAxis: frontNormal,
    })

    return {
      arm,
      armNumber,
      screen: [Math.round(clientX - rect.left), Math.round(clientY - rect.top)],
      ndc: [this.pointer.x, this.pointer.y],
      normalized: [u, v],
      radius,
      mode: radius <= 1 ? 'hemisphere' : 'boundary',
      reach: arm.reach,
      shoulderWorld,
      cursorPlaneWorld: cursorOnPlane,
      targetWorld,
      blocked: Boolean(blockedArc),
      blockedArc,
    }
  }

  getBlockedSphericalArc({
    armNumber,
    shoulderWorld,
    targetWorld,
    rightAxis,
    upAxis,
    frontAxis,
  }) {
    const arcs = BLOCKED_SPHERICAL_ARCS[armNumber]
    if (!arcs?.length) return null

    const targetDirection = targetWorld.clone().sub(shoulderWorld).normalize()
    const theta = Math.atan2(
      targetDirection.dot(upAxis),
      targetDirection.dot(rightAxis),
    )

    for (const arc of arcs) {
      const start = THREE.MathUtils.degToRad(arc.start)
      const end = THREE.MathUtils.degToRad(arc.end)
      const nearestAngle = this.getNearestAngleOnArc(theta, start, end)
      const nearestArcDirection = rightAxis
        .clone()
        .multiplyScalar(Math.cos(nearestAngle))
        .addScaledVector(upAxis, Math.sin(nearestAngle))
        .normalize()
      const angularDistance = Math.acos(
        THREE.MathUtils.clamp(targetDirection.dot(nearestArcDirection), -1, 1),
      )

      if (angularDistance <= BLOCKED_ARC_TOLERANCE) {
        return {
          id: arc.id,
          start: arc.start,
          end: arc.end,
          angle: THREE.MathUtils.radToDeg(theta),
          distance: THREE.MathUtils.radToDeg(angularDistance),
        }
      }
    }

    return this.getSupplementalBlockedArc({
      armNumber,
      shoulderWorld,
      targetWorld,
      rightAxis,
      upAxis,
      frontAxis,
    })
  }

  getNearestAngleOnArc(angle, start, end) {
    const fullTurn = Math.PI * 2
    const wrapPositive = (value) => ((value % fullTurn) + fullTurn) % fullTurn
    const arcLength = wrapPositive(end - start)
    const offset = wrapPositive(angle - start)
    if (offset <= arcLength) return angle

    const distanceToStart = Math.abs(Math.atan2(Math.sin(angle - start), Math.cos(angle - start)))
    const distanceToEnd = Math.abs(Math.atan2(Math.sin(angle - end), Math.cos(angle - end)))
    return distanceToStart <= distanceToEnd ? start : end
  }

  getSupplementalBlockedArc({
    armNumber,
    shoulderWorld,
    targetWorld,
    rightAxis,
    upAxis,
    frontAxis,
  }) {
    const targetDirection = targetWorld.clone().sub(shoulderWorld).normalize()
    const horizontalMirror = armNumber === 2 ? -1 : 1
    const arcPointSets = [
      { id: 3, source: [7, 13], points: SUPPLEMENTAL_BLOCKED_ARC_POINTS },
      { id: 4, source: ['image-1', 'image-2', 'image-3'], points: ADDITIONAL_BLOCKED_ARC_POINTS },
    ]

    for (const arc of arcPointSets) {
      const arcDirections = arc.points.map(([x, y, z]) =>
        rightAxis
          .clone()
          .multiplyScalar(x * horizontalMirror)
          .addScaledVector(upAxis, y)
          .addScaledVector(frontAxis, z)
          .normalize(),
      )

      for (let index = 0; index < arcDirections.length - 1; index += 1) {
        const nearestArcDirection = this.getNearestDirectionOnSphericalSegment(
          targetDirection,
          arcDirections[index],
          arcDirections[index + 1],
        )
        const angularDistance = Math.acos(
          THREE.MathUtils.clamp(targetDirection.dot(nearestArcDirection), -1, 1),
        )

        if (angularDistance <= BLOCKED_ARC_TOLERANCE) {
          return {
            id: arc.id,
            source: arc.source,
            segment: index + 1,
            distance: THREE.MathUtils.radToDeg(angularDistance),
          }
        }
      }
    }

    return null
  }

  getNearestDirectionOnSphericalSegment(target, start, end) {
    const segmentAngle = Math.acos(THREE.MathUtils.clamp(start.dot(end), -1, 1))
    const normal = new THREE.Vector3().crossVectors(start, end)
    if (normal.lengthSq() < 1e-10 || segmentAngle < 1e-6) return start

    normal.normalize()
    const projected = target.clone().addScaledVector(normal, -target.dot(normal))
    if (projected.lengthSq() < 1e-10) {
      return target.dot(start) >= target.dot(end) ? start : end
    }

    projected.normalize()
    if (projected.dot(target) < 0) projected.negate()

    const startToProjection = Math.acos(
      THREE.MathUtils.clamp(start.dot(projected), -1, 1),
    )
    const projectionToEnd = Math.acos(
      THREE.MathUtils.clamp(projected.dot(end), -1, 1),
    )
    if (startToProjection + projectionToEnd <= segmentAngle + 1e-5) {
      return projected
    }

    return target.dot(start) >= target.dot(end) ? start : end
  }

  setupCoordinateUi() {
    if (!this.coordinateUi) return

    const { exportButton, clearButton } = this.coordinateUi
    if (!exportButton || !clearButton) return

    exportButton.addEventListener('click', () => {
      this.exportCoordinateRecords()
    })
    clearButton.addEventListener('click', () => {
      if (!this.coordinateRecords.length) return
      if (clearButton.dataset.confirming !== 'true') {
        clearButton.dataset.confirming = 'true'
        clearButton.textContent = '确认清空'
        window.clearTimeout(this.clearConfirmationTimer)
        this.clearConfirmationTimer = window.setTimeout(() => {
          this.resetClearConfirmation()
        }, 3000)
        return
      }

      this.coordinateRecords = []
      localStorage.removeItem(this.coordinateStorageKey)
      this.resetClearConfirmation()
      this.renderCoordinateHistory()
    })
    this.renderCoordinateHistory()
  }

  setupParticleUi() {
    if (!this.particleUi) return

    const { input, output } = this.particleUi
    if (!input || !output) return
    input.value = String(this.particleSize)
    output.value = this.particleSize.toFixed(1)
    output.textContent = this.particleSize.toFixed(1)
    input.addEventListener('input', () => {
      this.particleSize = Number(input.value)
      output.value = this.particleSize.toFixed(1)
      output.textContent = this.particleSize.toFixed(1)
      this.orbitParticles?.setPointSize(this.particleSize)
      try {
        localStorage.setItem(this.particleStorageKey, String(this.particleSize))
      } catch {
        // The visual control remains usable when storage is unavailable.
      }
    })
  }

  loadParticleSize() {
    return DEFAULT_PARTICLE_SIZE
  }

  renderCoordinateTooltip(sample, clientX, clientY) {
    const tooltip = this.coordinateUi?.tooltip
    if (!tooltip) return

    const [u, v] = sample.normalized
    const target = sample.targetWorld.toArray().map((value) => value.toFixed(3))
    const mode = sample.blocked
      ? `禁用弧 ${sample.blockedArc.id}`
      : sample.mode === 'hemisphere'
        ? '半球内'
        : '圆外截断'
    tooltip.innerHTML = [
      `<strong>手臂 ${sample.armNumber}</strong> · ${mode}`,
      `screen  ${sample.screen[0]}, ${sample.screen[1]}`,
      `plane   u=${u.toFixed(3)}  v=${v.toFixed(3)}`,
      `radius  r=${sample.radius.toFixed(3)}`,
      `target  ${target.join(', ')}`,
    ].join('<br>')
    tooltip.classList.toggle('is-blocked', sample.blocked)
    tooltip.classList.add('is-visible')
    tooltip.setAttribute('aria-hidden', 'false')

    const bounds = tooltip.getBoundingClientRect()
    let left = clientX + 14
    let top = clientY + 14
    if (left + bounds.width > window.innerWidth - 8) left = clientX - bounds.width - 14
    if (top + bounds.height > window.innerHeight - 8) top = clientY - bounds.height - 14
    tooltip.style.left = `${Math.max(8, left)}px`
    tooltip.style.top = `${Math.max(8, top)}px`
  }

  hideCoordinateTooltip() {
    const tooltip = this.coordinateUi?.tooltip
    if (!tooltip) return
    tooltip.classList.remove('is-visible')
    tooltip.setAttribute('aria-hidden', 'true')
  }

  saveCoordinateRecord(sample) {
    const lastId = this.coordinateRecords.at(-1)?.id || 0
    const roundVector = (vector) => vector.toArray().map((value) => Number(value.toFixed(6)))
    const record = {
      id: lastId + 1,
      arm: sample.armNumber,
      screen: sample.screen,
      ndc: sample.ndc.map((value) => Number(value.toFixed(6))),
      normalized: sample.normalized.map((value) => Number(value.toFixed(6))),
      radius: Number(sample.radius.toFixed(6)),
      mode: sample.mode,
      reach: Number(sample.reach.toFixed(6)),
      shoulderWorld: roundVector(sample.shoulderWorld),
      cursorPlaneWorld: roundVector(sample.cursorPlaneWorld),
      targetWorld: roundVector(sample.targetWorld),
      blocked: sample.blocked,
      blockedArc: sample.blockedArc,
      timestamp: Date.now(),
    }

    this.coordinateRecords.push(record)
    try {
      localStorage.setItem(this.coordinateStorageKey, JSON.stringify(this.coordinateRecords))
    } catch (error) {
      console.warn('Coordinate records could not be saved.', error)
    }
    this.renderCoordinateHistory()
  }

  loadCoordinateRecords() {
    try {
      const records = JSON.parse(localStorage.getItem(this.coordinateStorageKey) || '[]')
      return Array.isArray(records) ? records : []
    } catch {
      return []
    }
  }

  renderCoordinateHistory() {
    if (!this.coordinateUi) return

    const { count, history, exportButton, clearButton } = this.coordinateUi
    if (!count || !history || !exportButton || !clearButton) return
    count.textContent = `${this.coordinateRecords.length} 个记录`
    exportButton.disabled = this.coordinateRecords.length === 0
    clearButton.disabled = this.coordinateRecords.length === 0
    history.replaceChildren()

    if (!this.coordinateRecords.length) {
      const empty = document.createElement('li')
      empty.className = 'empty-records'
      empty.textContent = '点击画布开始记录'
      history.appendChild(empty)
      return
    }

    this.coordinateRecords
      .slice(-8)
      .reverse()
      .forEach((record) => {
        const item = document.createElement('li')
        const id = document.createElement('span')
        const values = document.createElement('span')
        const mode = document.createElement('span')
        id.className = 'record-id'
        values.className = 'record-values'
        mode.className = 'record-mode'
        id.textContent = `#${record.id}`
        values.textContent = `臂${record.arm}  u ${record.normalized[0].toFixed(3)}  v ${record.normalized[1].toFixed(3)}  r ${record.radius.toFixed(3)}`
        mode.textContent = record.blocked
          ? `禁用${record.blockedArc?.id || ''}`
          : record.mode === 'hemisphere'
            ? '球内'
            : '圆周'
        item.classList.toggle('is-blocked', Boolean(record.blocked))
        item.append(id, values, mode)
        history.appendChild(item)
      })
  }

  resetClearConfirmation() {
    if (!this.coordinateUi?.clearButton) return
    window.clearTimeout(this.clearConfirmationTimer)
    this.clearConfirmationTimer = null
    this.coordinateUi.clearButton.dataset.confirming = 'false'
    this.coordinateUi.clearButton.textContent = '清空'
  }

  exportCoordinateRecords() {
    if (!this.coordinateRecords.length) return

    const payload = JSON.stringify(
      {
        version: 1,
        coordinateSystem: 'shoulder-plane-normalized-by-arm-length',
        exportedAt: new Date().toISOString(),
        records: this.coordinateRecords,
      },
      null,
      2,
    )
    const url = URL.createObjectURL(new Blob([payload], { type: 'application/json' }))
    const link = document.createElement('a')
    link.href = url
    link.download = 'robot-click-points.json'
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  setupArms() {
    const candidates = [
      {
        armRootName: 'Hand_LEFT',
        handName: 'Hand',
        fixedAnchorName: 'Rectangle',
        movingAnchorName: 'Rectangle_2',
        pivotName: 'ShoulderPivot_1',
      },
      {
        armRootName: 'Hand_LEFT001',
        handName: 'Hand002',
        fixedAnchorName: 'Rectangle001',
        movingAnchorName: 'Rectangle_2001',
        pivotName: 'ShoulderPivot_2',
      },
    ]

    this.model.updateMatrixWorld(true)
    this.arms = candidates
      .map(({ armRootName, handName, fixedAnchorName, movingAnchorName, pivotName }) => {
        const armRoot = this.findNode(this.model, armRootName)
        const hand = this.findNode(this.model, handName)
        const fixedAnchor = this.findNode(this.model, fixedAnchorName)
        const movingAnchor = this.findNode(this.model, movingAnchorName)
        if (!armRoot || !hand || !fixedAnchor || !movingAnchor || !this.body) return null

        const fixedCenterWorld = new THREE.Box3()
          .setFromObject(fixedAnchor)
          .getCenter(new THREE.Vector3())
        const shoulder = new THREE.Group()
        shoulder.name = pivotName
        shoulder.position.copy(this.body.worldToLocal(fixedCenterWorld.clone()))
        this.body.add(shoulder)
        this.model.updateMatrixWorld(true)

        shoulder.attach(armRoot)
        this.model.updateMatrixWorld(true)

        const movingCenterWorld = new THREE.Box3()
          .setFromObject(movingAnchor)
          .getCenter(new THREE.Vector3())
        const fixedCenterLocal = shoulder.worldToLocal(fixedCenterWorld.clone())
        const movingCenterLocal = shoulder.worldToLocal(movingCenterWorld)
        armRoot.position.add(fixedCenterLocal.sub(movingCenterLocal))
        this.model.updateMatrixWorld(true)

        const shoulderWorld = shoulder.getWorldPosition(new THREE.Vector3())
        const handWorld = hand.getWorldPosition(new THREE.Vector3())
        const reach = shoulderWorld.distanceTo(handWorld)
        const parentInverse = shoulder.parent.matrixWorld.clone().invert()
        const shoulderParent = shoulderWorld.clone().applyMatrix4(parentInverse)
        const handParent = handWorld.clone().applyMatrix4(parentInverse)

        return {
          shoulder,
          armRoot,
          hand,
          reach,
          restQuaternion: shoulder.quaternion.clone(),
          restDirectionParent: handParent.sub(shoulderParent).normalize(),
        }
      })
      .filter(Boolean)

    if (this.arms.length !== candidates.length) {
      console.warn('Robot arm nodes were not found in the loaded model.')
    }
  }

  createOrbitParticles() {
    this.model.updateMatrixWorld(true)
    const worldBounds = new THREE.Box3().setFromObject(this.model)
    const modelInverse = this.model.matrixWorld.clone().invert()
    const localBounds = worldBounds.clone().applyMatrix4(modelInverse)
    const localSize = localBounds.getSize(new THREE.Vector3())
    const shoulderCenters = this.arms.map((arm) =>
      arm.shoulder.getWorldPosition(new THREE.Vector3()).applyMatrix4(modelInverse),
    )
    const axisCenter = shoulderCenters[0]
      .clone()
      .add(shoulderCenters[1])
      .multiplyScalar(0.5)
    const horizontalRadius = Math.max(localSize.x, localSize.z) * 0.5
    const heightPadding = localSize.y * 0.06

    const minHeight = localBounds.min.y - heightPadding
    const maxHeight = localBounds.max.y + heightPadding
    const minRadius = horizontalRadius * 1.15
    const maxRadius = horizontalRadius * 2.25
    const pixelRatio = Math.min(window.devicePixelRatio || 1, 2)

    this.orbitParticles = new OrbitParticles({
      count: 220,
      center: axisCenter,
      minHeight,
      maxHeight,
      minRadius,
      maxRadius,
      pointSize: this.particleSize,
      pixelRatio,
    })
    this.model.add(this.orbitParticles)

    this.featureParticle = new FeatureParticle({
      center: axisCenter,
      radius: minRadius,
      height: THREE.MathUtils.lerp(minHeight, maxHeight, 0.68),
      angle: 1.15,
      speed: 0.03,
      pointSize: FEATURE_PARTICLE_SIZE,
      pixelRatio,
    })
    this.model.add(this.featureParticle)
  }

  createTargetMarker() {
    const geometry = new THREE.RingGeometry(0.055, 0.085, 32)
    const material = new THREE.MeshBasicMaterial({
      color: 0x8ee7ff,
      transparent: true,
      opacity: 0,
      depthTest: false,
      side: THREE.DoubleSide,
    })
    this.targetMarker = new THREE.Mesh(geometry, material)
    this.targetMarker.renderOrder = 10
    this.targetMarker.visible = false
    this.scene.add(this.targetMarker)
  }

  updateFeatureLabel() {
    const label = this.transitionUi?.label
    if (!label || !this.featureParticle || this.interactionState !== 'orbiting') {
      label?.classList.remove('is-visible')
      return
    }

    const worldPosition = this.featureParticle.getWorldPosition(new THREE.Vector3())
    const projected = worldPosition.project(this.camera)
    const rect = this.stage.getBoundingClientRect()
    const visible = projected.z >= -1 && projected.z <= 1
      && projected.x >= -1.15 && projected.x <= 1.15
      && projected.y >= -1.15 && projected.y <= 1.15

    if (!visible) {
      label.classList.remove('is-visible')
      return
    }

    label.style.left = `${(projected.x + 1) * 0.5 * rect.width}px`
    label.style.top = `${(1 - projected.y) * 0.5 * rect.height - 12}px`
    label.classList.add('is-visible')
  }

  updateStatusBubblePosition() {
    const bubble = this.statusBubbleRef?.current
    if (!bubble || !this.head || !this.camera) return

    this.model.updateMatrixWorld(true)
    this.camera.updateMatrixWorld()
    const bounds = this.statusHeadBounds.setFromObject(this.head)
    if (bounds.isEmpty()) return

    const stageRect = this.stage.getBoundingClientRect()
    let screenLeft = Number.POSITIVE_INFINITY
    let screenRight = Number.NEGATIVE_INFINITY
    let screenTop = Number.POSITIVE_INFINITY
    let screenBottom = Number.NEGATIVE_INFINITY
    let visible = false
    for (const x of [bounds.min.x, bounds.max.x]) {
      for (const y of [bounds.min.y, bounds.max.y]) {
        for (const z of [bounds.min.z, bounds.max.z]) {
          this.statusHeadCorner.set(x, y, z).project(this.camera)
          if (this.statusHeadCorner.z < -1 || this.statusHeadCorner.z > 1) continue
          visible = true
          const projectedX = stageRect.left + (this.statusHeadCorner.x + 1) * 0.5 * stageRect.width
          const projectedY = stageRect.top + (1 - this.statusHeadCorner.y) * 0.5 * stageRect.height
          screenLeft = Math.min(screenLeft, projectedX)
          screenRight = Math.max(screenRight, projectedX)
          screenTop = Math.min(screenTop, projectedY)
          screenBottom = Math.max(screenBottom, projectedY)
        }
      }
    }

    if (!visible) {
      bubble.classList.remove('is-positioned')
      return
    }

    const bubbleHeight = bubble.offsetHeight || 44
    const bubbleWidth = bubble.offsetWidth || 44
    const headCenterY = (screenTop + screenBottom) * 0.5
    const gap = Math.max(12, (screenRight - screenLeft) * 0.18)
    const cockpitHeaderBottom = document.querySelector('.cockpit-head')?.getBoundingClientRect().bottom ?? 76
    const topClearance = Math.max(88, cockpitHeaderBottom + 12)
    const leftLimit = Math.max(12, stageRect.left + 12)
    const rightLimit = Math.min(window.innerWidth - 12, stageRect.right - 12)
    const leftCandidate = screenLeft - gap
    const rightCandidate = screenRight + gap
    const fitsLeft = leftCandidate - bubbleWidth >= leftLimit && leftCandidate <= rightLimit
    const fitsRight = rightCandidate >= leftLimit && rightCandidate + bubbleWidth <= rightLimit
    let side
    let targetX
    let targetY = headCenterY
    if (fitsLeft) {
      side = 'left'
      targetX = leftCandidate
    } else if (fitsRight) {
      side = 'right'
      targetX = rightCandidate
    } else {
      const canFitAbove = window.innerWidth > 760 && screenTop - bubbleHeight - gap >= topClearance
      side = canFitAbove ? 'top' : 'bottom'
      targetX = (screenLeft + screenRight) * 0.5
      targetY = canFitAbove ? screenTop - gap : screenBottom + gap
    }
    const minX = side === 'left' ? leftLimit + bubbleWidth : side === 'right' ? leftLimit : leftLimit + bubbleWidth * 0.5
    const maxX = side === 'left' || side === 'right' ? rightLimit - (side === 'left' ? 0 : bubbleWidth) : rightLimit - bubbleWidth * 0.5
    const safeX = THREE.MathUtils.clamp(targetX, minX, Math.max(minX, maxX))
    const minY = side === 'top' ? topClearance + bubbleHeight : bubbleHeight * 0.5 + 12
    const maxY = side === 'top' ? window.innerHeight - bubbleHeight * 0.5 - 12 : window.innerHeight - bubbleHeight - 12
    const safeY = THREE.MathUtils.clamp(targetY, minY, Math.max(minY, maxY))

    bubble.style.left = `${safeX}px`
    bubble.style.top = `${safeY}px`
    bubble.dataset.side = side
    bubble.classList.add('is-positioned')
  }

  handlePointerDown(event) {
    if (this.arms.length !== 2 || !this.model || this.interactionState !== 'orbiting') return

    if (this.handleFeatureParticleClick(event)) return

    const sample = this.getPointerSample(event.clientX, event.clientY)
    if (!sample) return

    this.saveCoordinateRecord(sample)
    if (sample.blocked) return

    const targetQuaternion = this.getReachQuaternion(
      sample.arm,
      sample.shoulderWorld,
      sample.targetWorld,
    )

    this.animateReach(sample.arm, targetQuaternion, sample.targetWorld)
  }

  handleFeatureParticleClick(event) {
    if (!this.featureParticle?.visible) return false

    const rect = this.renderer.domElement.getBoundingClientRect()
    if (rect.width <= 0 || rect.height <= 0) return false

    this.pointer.set(
      ((event.clientX - rect.left) / rect.width) * 2 - 1,
      -((event.clientY - rect.top) / rect.height) * 2 + 1,
    )
    this.model.updateMatrixWorld(true)
    const targetWorld = this.featureParticle.getWorldPosition(new THREE.Vector3())
    const projectedTarget = targetWorld.clone().project(this.camera)
    const targetScreenX = rect.left + (projectedTarget.x + 1) * 0.5 * rect.width
    const targetScreenY = rect.top + (1 - projectedTarget.y) * 0.5 * rect.height
    const pointerDistance = Math.hypot(
      event.clientX - targetScreenX,
      event.clientY - targetScreenY,
    )
    if (projectedTarget.z < -1 || projectedTarget.z > 1 || pointerDistance > 48) return false

    this.interactionState = 'reaching'
    this.transitionUi?.label?.classList.remove('is-visible')

    const arm = this.selectArmForPointer(this.pointer.x)
    const shoulderWorld = arm.shoulder.getWorldPosition(new THREE.Vector3())
    const targetQuaternion = this.getReachQuaternion(arm, shoulderWorld, targetWorld)

    console.info('[feature-entry] selected', { target: targetWorld.toArray() })
    this.animateReach(arm, targetQuaternion, targetWorld, {
      holdAtTarget: true,
      onContact: () => this.startFeatureExplosion(targetWorld),
    })
    return true
  }

  startFeatureExplosion(targetWorld) {
    if (this.interactionState !== 'reaching') return

    this.interactionState = 'exploding'
    this.featureParticle.setVisible(false)
    this.targetMarker.visible = false
    this.particleExplosion?.removeFromParent()
    this.particleExplosion = new ParticleExplosion({
      center: targetWorld,
      count: 160,
      duration: 1.15,
    })
    this.scene.add(this.particleExplosion)

    const overlay = this.transitionUi?.overlay
    if (!overlay) {
      this.completeFeatureNavigation()
      return
    }

    gsap.to(overlay, {
      opacity: 1,
      duration: 1.35,
      ease: 'power2.inOut',
    })
    window.clearTimeout(this.navigationTimer)
    this.navigationTimer = window.setTimeout(
      () => this.completeFeatureNavigation(),
      1400,
    )
  }

  completeFeatureNavigation() {
    if (this.interactionState === 'navigating') return
    this.interactionState = 'navigating'
    window.clearTimeout(this.navigationTimer)
    this.navigationTimer = null

    const targetUrl = new URL('/workbench', window.location.origin)
    targetUrl.searchParams.set('source', 'feature-entry')
    console.info('[feature-entry] navigation', targetUrl.href)
    window.location.assign(targetUrl.href)
  }

  selectArmForPointer(pointerX) {
    const sorted = this.getScreenOrderedArms()
    const leftX = sorted[0].shoulder.getWorldPosition(new THREE.Vector3()).project(this.camera).x
    const rightX = sorted[1].shoulder.getWorldPosition(new THREE.Vector3()).project(this.camera).x
    return pointerX < (leftX + rightX) * 0.5 ? sorted[0] : sorted[1]
  }

  getScreenOrderedArms() {
    return [...this.arms].sort((a, b) => {
      const aX = a.shoulder.getWorldPosition(new THREE.Vector3()).project(this.camera).x
      const bX = b.shoulder.getWorldPosition(new THREE.Vector3()).project(this.camera).x
      return aX - bX
    })
  }

  getReachTarget(shoulderWorld, reach) {
    const frontNormal = this.getFrontNormal(shoulderWorld)
    const boundaryPlane = new THREE.Plane().setFromNormalAndCoplanarPoint(
      frontNormal,
      shoulderWorld,
    )
    const cursorOnPlane = this.raycaster.ray.intersectPlane(
      boundaryPlane,
      new THREE.Vector3(),
    )

    if (!cursorOnPlane) {
      return shoulderWorld.clone().addScaledVector(frontNormal, reach)
    }

    const planarDirection = cursorOnPlane.clone().sub(shoulderWorld)
    const planarDistance = planarDirection.length()

    // Outside the projected reach circle, clamp to its radial boundary.
    if (planarDistance >= reach) {
      if (planarDistance < 0.000001) planarDirection.set(0, 1, 0)
      return shoulderWorld
        .clone()
        .addScaledVector(planarDirection.normalize(), reach)
    }

    const sphere = new THREE.Sphere(shoulderWorld, reach)
    const intersection = this.raycaster.ray.intersectSphere(sphere, new THREE.Vector3())
    if (
      intersection &&
      intersection.clone().sub(shoulderWorld).dot(frontNormal) >= 0
    ) {
      return intersection
    }

    // Numerical fallback for points inside the projected circle.
    const depth = Math.sqrt(Math.max(reach * reach - planarDistance * planarDistance, 0))
    return cursorOnPlane.addScaledVector(frontNormal, depth)
  }

  getFrontNormal(shoulderWorld) {
    const normal = new THREE.Vector3(0, 0, 1).transformDirection(this.body.matrixWorld)
    const towardCamera = this.camera.position.clone().sub(shoulderWorld)
    if (normal.dot(towardCamera) < 0) normal.negate()
    return normal.normalize()
  }

  getReachQuaternion(arm, shoulderWorld, targetWorld) {
    const parentInverse = arm.shoulder.parent.matrixWorld.clone().invert()
    const shoulderParent = shoulderWorld.clone().applyMatrix4(parentInverse)
    const targetDirectionParent = targetWorld
      .clone()
      .applyMatrix4(parentInverse)
      .sub(shoulderParent)
      .normalize()
    const delta = new THREE.Quaternion().setFromUnitVectors(
      arm.restDirectionParent,
      targetDirectionParent,
    )
    return delta.multiply(arm.restQuaternion.clone()).normalize()
  }

  animateReach(arm, targetQuaternion, targetWorld, options = {}) {
    const { holdAtTarget = false, onContact = null } = options
    if (this.reachTimeline) this.reachTimeline.kill()
    this.isReaching = true
    this.arms.forEach((item) => {
      gsap.killTweensOf(item.shoulder.quaternion)
      if (item !== arm) item.shoulder.quaternion.copy(item.restQuaternion)
    })

    this.targetMarker.position.copy(targetWorld)
    this.targetMarker.quaternion.copy(this.camera.quaternion)
    this.targetMarker.scale.setScalar(0.65)
    this.targetMarker.material.opacity = 0
    this.targetMarker.visible = true

    const startQuaternion = arm.shoulder.quaternion.clone()
    const reachProgress = { value: 0 }
    const returnProgress = { value: 0 }

    this.reachTimeline = gsap.timeline({
      onComplete: () => {
        this.targetMarker.visible = false
        this.isReaching = false
        this.reachTimeline = null
      },
    })
    this.reachTimeline
      .to(this.targetMarker.material, { opacity: 0.9, duration: 0.16 }, 0)
      .to(this.targetMarker.scale, { x: 1, y: 1, z: 1, duration: 0.35 }, 0)
      .to(
        reachProgress,
        {
          value: 1,
          duration: 0.65,
          ease: 'power2.inOut',
          onUpdate: () => {
            arm.shoulder.quaternion.slerpQuaternions(
              startQuaternion,
              targetQuaternion,
              reachProgress.value,
            )
          },
        },
        0,
      )

    if (holdAtTarget) {
      this.reachTimeline
        .to({}, { duration: 0.14 })
        .call(() => onContact?.())
      return
    }

    this.reachTimeline
      .to({}, { duration: 0.8 })
      .to(this.targetMarker.material, { opacity: 0, duration: 0.3 }, '<')
      .to(
        returnProgress,
        {
          value: 1,
          duration: 0.7,
          ease: 'power2.inOut',
          onUpdate: () => {
            arm.shoulder.quaternion.slerpQuaternions(
              targetQuaternion,
              arm.restQuaternion,
              returnProgress.value,
            )
          },
        },
      )
  }

  getMouseDegrees(x, y, degreeLimit) {
    const width = window.innerWidth
    const height = window.innerHeight
    const dx = ((x - width / 2) / (width / 2)) * degreeLimit
    const dy = ((y - height / 2) / (height / 2)) * degreeLimit

    return {
      x: THREE.MathUtils.clamp(dx, -degreeLimit, degreeLimit),
      y: THREE.MathUtils.clamp(dy * 0.5, -degreeLimit, degreeLimit),
    }
  }

  findNode(root, name) {
    if (!root) return null
    if (root.name === name) return root

    for (const child of root.children || []) {
      const match = this.findNode(child, name)
      if (match) return match
    }

    return null
  }

  hideLoading() {
    if (!this.loading) return
    this.loading.classList.add('is-hidden')
  }

  destroy() {
    window.removeEventListener('resize', this.handleResize)
    window.removeEventListener('mousemove', this.handleMouseMove)
    this.renderer?.domElement.removeEventListener('pointermove', this.handleSamplingPointerMove)
    this.renderer?.domElement.removeEventListener('pointerdown', this.handlePointerDown)
    this.renderer?.domElement.removeEventListener('pointerleave', this.hideCoordinateTooltip)
    if (this.frameId !== null) window.cancelAnimationFrame(this.frameId)
    this.navigationTimer && window.clearTimeout(this.navigationTimer)
    this.reachTimeline?.kill()
    this.renderer?.dispose()
    this.renderer?.domElement.remove()
    this.orbitParticles?.geometry?.dispose()
    this.featureParticle?.geometry?.dispose()
    this.particleExplosion?.geometry?.dispose()
  }
}
