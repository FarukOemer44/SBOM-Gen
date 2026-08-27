import React from 'react'
import Shell from './Shell.jsx'
import { StoreProvider } from './store.jsx'
import { I18nProvider } from './i18n.jsx'
import SbomTool from './pages/SbomTool.jsx'

export default function App() {
  return (
    <I18nProvider>
      <StoreProvider>
        <Shell><SbomTool /></Shell>
      </StoreProvider>
    </I18nProvider>
  )
}
