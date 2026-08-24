
interface ScoreGaugeProps {
  score: number
  size?: number
  strokeWidth?: number
}

export function ScoreGauge({ score, size = 80, strokeWidth = 6 }: ScoreGaugeProps) {
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference
  
  const color = score >= 80 ? '#3fb950' : score >= 50 ? '#d29922' : '#f85149'
  
  return (
    <div className="gauge-container">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle className="gauge-bg" cx={size/2} cy={size/2} r={radius} />
        <circle
          className="gauge-fill"
          cx={size/2} cy={size/2} r={radius}
          stroke={color}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
        <text className="gauge-text" x={size/2} y={size/2} textAnchor="middle" dominantBaseline="central" style={{ transform: 'rotate(90deg)', transformOrigin: 'center' }}>
          {score}
        </text>
      </svg>
      <span className="gauge-label">Security Score</span>
    </div>
  )
}
