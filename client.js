window.__ModuleLoader__.load({
  id: 'dsh-push-privacy-guard',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    function label() {
      const language = String(globalThis.navigator?.language ?? 'zh').toLowerCase()
      return language.startsWith('zh') ? '隐私检查' : 'Privacy Guard'
    }

    function SettingsPage() {
      return h('iframe', {
        src: '/privacy-guard/settings',
        title: 'Push Privacy Guard settings',
        style: {
          width: '100%',
          height: '78vh',
          minHeight: '560px',
          border: 'none',
          borderRadius: '12px',
          background: 'transparent',
          display: 'block',
        },
      })
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('settings.section', () => ctx.slots.register({
          name: 'settings.section',
          id: 'push-privacy-guard',
          order: 200,
          label,
        }, SettingsPage))
      },
    }
  },
})
