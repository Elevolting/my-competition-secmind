export function reconcileBlackboardElements(nextElements, currentElements, resetPositions = false) {
  const positions = new Map(
    currentElements
      .filter((element) => element.group === 'nodes' && element.position)
      .map((element) => [element.data.id, element.position]),
  )

  return nextElements.map((element) => {
    if (resetPositions || element.group !== 'nodes') return element
    const position = positions.get(element.data.id)
    return position ? { ...element, position } : element
  })
}

export function updateSelectedBlackboardNode(selected, nodes) {
  if (!selected) return null
  const updated = nodes.find((node) => node.id === selected.id)
  return updated ? { ...selected, ...updated } : null
}
