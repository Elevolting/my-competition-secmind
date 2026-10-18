import * as THREE from 'three'

const vertexShader = /* glsl */ `
  uniform float uTime;
  uniform float uPointSize;
  uniform float uPixelRatio;

  varying float vPulse;

  void main() {
    vec4 viewPosition = modelViewMatrix * vec4(position, 1.0);
    gl_Position = projectionMatrix * viewPosition;
    gl_PointSize = clamp(
      uPointSize * uPixelRatio * (6.0 / max(-viewPosition.z, 0.1)),
      10.0,
      96.0
    );
    vPulse = 0.78 + 0.22 * sin(uTime * 2.4);
  }
`

const fragmentShader = /* glsl */ `
  varying float vPulse;

  void main() {
    vec2 point = gl_PointCoord - vec2(0.5);
    float distanceToCenter = length(point) * 2.0;
    if (distanceToCenter > 1.0) discard;

    float halo = exp(-distanceToCenter * distanceToCenter * 3.0);
    float core = 1.0 - smoothstep(0.08, 0.48, distanceToCenter);
    float alpha = (halo * 0.62 + core * 0.38) * vPulse;
    vec3 color = mix(vec3(0.42, 0.86, 1.0), vec3(0.95, 1.0, 1.0), core);

    gl_FragColor = vec4(color, alpha);
  }
`

export class FeatureParticle extends THREE.Group {
  constructor({
    center = new THREE.Vector3(),
    radius = 3,
    height = 1,
    angle = 0.6,
    speed = 0.12,
    pointSize = 44,
    pixelRatio = 1,
  } = {}) {
    super()

    this.name = 'FeatureParticle'
    this.center = center.clone()
    this.radius = radius
    this.height = height
    this.angle = angle
    this.speed = speed

    const visualGeometry = new THREE.BufferGeometry()
    visualGeometry.setAttribute(
      'position',
      new THREE.Float32BufferAttribute([0, 0, 0], 3),
    )
    const visualMaterial = new THREE.ShaderMaterial({
      uniforms: {
        uTime: { value: 0 },
        uPointSize: { value: pointSize },
        uPixelRatio: { value: pixelRatio },
      },
      vertexShader,
      fragmentShader,
      transparent: true,
      depthTest: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      toneMapped: false,
    })
    this.visual = new THREE.Points(visualGeometry, visualMaterial)
    this.visual.frustumCulled = false
    this.visual.renderOrder = 3

    const hitMaterial = new THREE.MeshBasicMaterial({
      transparent: true,
      opacity: 0,
      depthWrite: false,
    })
    this.hitTarget = new THREE.Mesh(new THREE.SphereGeometry(0.22, 12, 8), hitMaterial)
    this.hitTarget.name = 'FeatureParticleHitTarget'
    this.hitTarget.userData.isFeatureParticle = true

    this.add(this.visual, this.hitTarget)
    this.update(0)
  }

  update(elapsedTime) {
    const orbitAngle = this.angle - elapsedTime * this.speed
    this.position.set(
      this.center.x + Math.cos(orbitAngle) * this.radius,
      this.height,
      this.center.z + Math.sin(orbitAngle) * this.radius,
    )
    this.visual.material.uniforms.uTime.value = elapsedTime
  }

  setPixelRatio(pixelRatio) {
    this.visual.material.uniforms.uPixelRatio.value = pixelRatio
  }

  setVisible(visible) {
    this.visible = visible
  }
}
