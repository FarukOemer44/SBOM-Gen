import React from 'react'
import Shell from './Shell.jsx'
import { StoreProvider } from './store.jsx'
import SbomTool from './pages/SbomTool.jsx'

export default function App() {
  return (
    <StoreProvider>
      <Shell><SbomTool /></Shell>
    </StoreProvider>
  )
}
