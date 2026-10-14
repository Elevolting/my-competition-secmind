import React, { useEffect, useRef } from 'react'
import { RobotHero } from '../robot/RobotHero.js'

export function RobotCanvas({ statusBubbleRef }) {
  const stageRef = useRef(null)
  const loadingRef = useRef(null)

  useEffect(() => {
    if (!stageRef.current) return undefined
    const robot = new RobotHero(stageRef.current, loadingRef.current, null, null, null, statusBubbleRef)
    robot.init().catch((error) => {
      console.error('[robot] failed to initialise', error)
      if (loadingRef.current) {
        loadingRef.current.textContent = '3D model failed to load'
        loadingRef.current.classList.add('has-error')
      }
    })
    return () => robot.destroy()
  }, [])

  return <>
    <div className="hero-stage" ref={stageRef} aria-label="3D 安全运营机器人" />
    <div className="hero-loading" ref={loadingRef}>Loading 3D model…</div>
  </>
}
