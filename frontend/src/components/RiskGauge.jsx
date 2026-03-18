import { useEffect, useMemo, useState } from 'react'

function riskColor(score) {
  if (score >= 75) return '#c1121f'
  if (score >= 50) return '#e36414'
  if (score >= 25) return '#f2a900'
  return '#1f9d55'
}

export default function RiskGauge({ score = 0 }) {
  const size = 210
  const stroke = 14
  const radius = (size - stroke) / 2
  const circumference = 2 * Math.PI * radius
  const [displayScore, setDisplayScore] = useState(0)

  useEffect(() => {
    let frame = null
    const start = performance.now()
    const duration = 1200
    const target = Math.max(0, Math.min(100, score))

    const animate = (time) => {
      const progress = Math.min(1, (time - start) / duration)
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplayScore(Math.round(target * eased))
      if (progress < 1) frame = requestAnimationFrame(animate)
    }

    frame = requestAnimationFrame(animate)
    return () => {
      if (frame) cancelAnimationFrame(frame)
    }
  }, [score])

  const offset = useMemo(() => circumference - (displayScore / 100) * circumference, [displayScore, circumference])
  const color = riskColor(displayScore)

  return (
    <div className="gauge-wrap" aria-label="Risk score gauge">
      <svg width={size} height={size} className="gauge-svg">
        <circle
          className="gauge-bg"
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={stroke}
          fill="none"
        />
        <circle
          className="gauge-meter"
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={stroke}
          fill="none"
          stroke={color}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
      </svg>
      <div className="gauge-content">
        <span className="gauge-score">{displayScore}</span>
        <span className="gauge-total">/100</span>
        <span className="gauge-label">Risk Score</span>
      </div>
    </div>
  )
}
