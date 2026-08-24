import { useEffect, useRef, useState } from 'react'

interface SseOptions {
  url: string
  onMessage?: (data: unknown) => void
  onOpen?: () => void
  onError?: (err: Event) => void
  onClose?: () => void
}

export function useSse(options: SseOptions) {
  const [connected, setConnected] = useState(false)
  const evtSourceRef = useRef<EventSource | null>(null)

  useEffect(() => {
    const { url, onMessage, onOpen, onError, onClose } = options
    const evt = new EventSource(url)
    evtSourceRef.current = evt

    evt.onopen = () => { setConnected(true); onOpen?.() }
    evt.onmessage = (e) => {
      try { onMessage?.(JSON.parse(e.data)) } catch { onMessage?.(e.data) }
    }
    evt.onerror = (e) => { setConnected(false); onError?.(e) }
    evt.addEventListener('close', () => { setConnected(false); onClose?.() })

    return () => { evt.close() }
  }, [options.url]) // eslint-disable-line react-hooks/exhaustive-deps

  return { connected }
}
