import * as THREE from 'three'

const vertexShader = /* glsl */ `
  uniform float uTime;
  uniform float uPointSize;
  uniform float uPixelRatio;
  uniform vec3 uCenter;

  attribute float aRadius;
  attribute float aHeight;
  attribute float aAngle;
  attribute float aOrbitSpeed;
  attribute float aSize;
  attribute float aPulseSpeed;
  attribute float aPulsePhase;
  attribute vec3 aColor;

  varying vec3 vColor;
  varying float vBrightness;

  void main() {
    float angle = aAngle - uTime * aOrbitSpeed;
    vec3 orbitPosition = vec3(
      uCenter.x + cos(angle) * aRadius,
      aHeight,
      uCenter.z + sin(angle) * aRadius
    );

    vec4 viewPosition = modelViewMatrix * vec4(orbitPosition, 1.0);
    gl_Position = projectionMatrix * viewPosition;
    gl_PointSize = clamp(
      uPointSize * aSize * uPixelRatio * (6.0 / max(-viewPosition.z, 0.1)),
      1.0,
      48.0
    );

    float pulse = 0.5 + 0.5 * sin(uTime * aPulseSpeed + aPulsePhase);
    vBrightness = mix(0.32, 1.0, pulse);
    vColor = aColor;
  }
`

const fragmentShader = /* glsl */ `
  varying vec3 vColor;
  varying float vBrightness;

  void main() {
    vec2 point = gl_PointCoord - vec2(0.5);
    float distanceToCenter = length(point) * 2.0;
    if (distanceToCenter > 1.0) discard;

    float halo = exp(-distanceToCenter * distanceToCenter * 3.8);
    float core = smoothstep(0.42, 0.0, distanceToCenter);
    float alpha = (halo * 0.72 + core * 0.28) * vBrightness;
    vec3 color = vColor * mix(0.7, 1.35, vBrightness);

    gl_FragColor = vec4(color, alpha);
  }
`

export class OrbitParticles extends THREE.Points {
  constructor({
    count = 220,
    center = new THREE.Vector3(),
    minHeight = -2,
    maxHeight = 2,
    minRadius = 2,
    maxRadius = 4,
    pointSize = 10,
    pixelRatio = 1,
  } = {}) {
    const geometry = new THREE.BufferGeometry()
    const material = new THREE.ShaderMaterial({
      uniforms: {
        uTime: { value: 0 },
        uPointSize: { value: pointSize },
        uPixelRatio: { value: pixelRatio },
        uCenter: { value: center.clone() },
      },
      vertexShader,
      fragmentShader,
      transparent: true,
      depthTest: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      toneMapped: false,
    })

    const positions = new Float32Array(count * 3)
    const radii = new Float32Array(count)
    const heights = new Float32Array(count)
    const angles = new Float32Array(count)
    const orbitSpeeds = new Float32Array(count)
    const sizes = new Float32Array(count)
    const pulseSpeeds = new Float32Array(count)
    const pulsePhases = new Float32Array(count)
    const colors = new Float32Array(count * 3)
    const white = new THREE.Color(0xf2fbff)
    const cyan = new THREE.Color(0x82dfff)

    for (let index = 0; index < count; index += 1) {
      radii[index] = THREE.MathUtils.lerp(minRadius, maxRadius, Math.random())
      heights[index] = THREE.MathUtils.lerp(minHeight, maxHeight, Math.random())
      angles[index] = Math.random() * Math.PI * 2
      orbitSpeeds[index] = THREE.MathUtils.lerp(0.08, 0.24, Math.random())
      sizes[index] = THREE.MathUtils.lerp(0.68, 1.35, Math.random())
      pulseSpeeds[index] = THREE.MathUtils.lerp(1.8, 5.2, Math.random())
      pulsePhases[index] = Math.random() * Math.PI * 2

      const color = white.clone().lerp(cyan, Math.random() * 0.38)
      colors[index * 3] = color.r
      colors[index * 3 + 1] = color.g
      colors[index * 3 + 2] = color.b
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3))
    geometry.setAttribute('aRadius', new THREE.BufferAttribute(radii, 1))
    geometry.setAttribute('aHeight', new THREE.BufferAttribute(heights, 1))
    geometry.setAttribute('aAngle', new THREE.BufferAttribute(angles, 1))
    geometry.setAttribute('aOrbitSpeed', new THREE.BufferAttribute(orbitSpeeds, 1))
    geometry.setAttribute('aSize', new THREE.BufferAttribute(sizes, 1))
    geometry.setAttribute('aPulseSpeed', new THREE.BufferAttribute(pulseSpeeds, 1))
    geometry.setAttribute('aPulsePhase', new THREE.BufferAttribute(pulsePhases, 1))
    geometry.setAttribute('aColor', new THREE.BufferAttribute(colors, 3))

    super(geometry, material)
    this.name = 'OrbitParticles'
    this.frustumCulled = false
    this.renderOrder = 2
  }

  update(elapsedTime) {
    this.material.uniforms.uTime.value = elapsedTime
  }

  setPointSize(size) {
    this.material.uniforms.uPointSize.value = size
  }

  setPixelRatio(pixelRatio) {
    this.material.uniforms.uPixelRatio.value = pixelRatio
  }
}
