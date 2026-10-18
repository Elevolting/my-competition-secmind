import * as THREE from 'three'

const vertexShader = /* glsl */ `
  uniform float uTime;
  uniform float uDuration;
  uniform float uPixelRatio;

  attribute vec3 aDirection;
  attribute float aSpeed;
  attribute float aSize;

  varying float vLife;

  void main() {
    float progress = clamp(uTime / uDuration, 0.0, 1.0);
    float drag = 3.4;
    float travel = aSpeed * (1.0 - exp(-drag * uTime)) / drag;
    vec3 displaced = position + aDirection * travel;
    vec4 viewPosition = modelViewMatrix * vec4(displaced, 1.0);
    gl_Position = projectionMatrix * viewPosition;
    gl_PointSize = clamp(
      5.0 * aSize * uPixelRatio * (6.0 / max(-viewPosition.z, 0.1)) * (1.0 - progress * 0.7),
      1.0,
      18.0
    );
    vLife = 1.0 - smoothstep(0.48, 1.0, progress);
  }
`

const fragmentShader = /* glsl */ `
  varying float vLife;

  void main() {
    vec2 pixel = step(vec2(0.18), gl_PointCoord) * step(gl_PointCoord, vec2(0.82));
    float square = pixel.x * pixel.y;
    if (square < 0.5) discard;
    gl_FragColor = vec4(1.0, 0.05, 0.02, square * vLife);
  }
`

export class ParticleExplosion extends THREE.Points {
  constructor({ center = new THREE.Vector3(), count = 160, duration = 1.15 } = {}) {
    const positions = new Float32Array(count * 3)
    const directions = new Float32Array(count * 3)
    const speeds = new Float32Array(count)
    const sizes = new Float32Array(count)

    for (let index = 0; index < count; index += 1) {
      positions[index * 3] = center.x
      positions[index * 3 + 1] = center.y
      positions[index * 3 + 2] = center.z

      const direction = new THREE.Vector3(
        Math.random() * 2 - 1,
        Math.random() * 2 - 1,
        Math.random() * 2 - 1,
      ).normalize()
      directions[index * 3] = direction.x
      directions[index * 3 + 1] = direction.y
      directions[index * 3 + 2] = direction.z
      speeds[index] = THREE.MathUtils.lerp(0.65, 1.45, Math.random())
      sizes[index] = THREE.MathUtils.lerp(0.55, 1.15, Math.random())
    }

    const geometry = new THREE.BufferGeometry()
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3))
    geometry.setAttribute('aDirection', new THREE.BufferAttribute(directions, 3))
    geometry.setAttribute('aSpeed', new THREE.BufferAttribute(speeds, 1))
    geometry.setAttribute('aSize', new THREE.BufferAttribute(sizes, 1))

    const material = new THREE.ShaderMaterial({
      uniforms: {
        uTime: { value: 0 },
        uDuration: { value: duration },
        uPixelRatio: { value: Math.min(window.devicePixelRatio || 1, 2) },
      },
      vertexShader,
      fragmentShader,
      transparent: true,
      depthTest: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      toneMapped: false,
    })

    super(geometry, material)
    this.name = 'ParticleExplosion'
    this.duration = duration
    this.frustumCulled = false
    this.renderOrder = 8
  }

  update(deltaTime) {
    this.material.uniforms.uTime.value += deltaTime
    return this.material.uniforms.uTime.value < this.duration
  }

  setPixelRatio(pixelRatio) {
    this.material.uniforms.uPixelRatio.value = pixelRatio
  }
}
