import { Card, Notice, Page, PageHeader } from '../components/Console'
import { KillSwitchControl } from '../components/KillSwitch'
import { can, PERMISSION, useMe } from '../lib/useMe'

export default function AdminPage() {
  const { me } = useMe()
  if (!can(me, PERMISSION.killSwitchWrite)) {
    return <Page><PageHeader title="Admin" /><Notice>Your role ({me?.role ?? 'unknown'}) has no admin controls. The kill-switch status is always shown in the top bar.</Notice></Page>
  }
  return (
    <Page>
      <PageHeader title="Admin" description="Controls for platform operators. Every change is recorded with your identity." />
      <Card className="max-w-2xl space-y-3">
        <h2 className="text-base font-semibold">Global kill switch</h2>
        <p className="text-muted">Halts every running campaign for every organisation within one turn and blocks new launches until released. The backend limits the toggle to platform admins; everyone else only sees its status in the top bar.</p>
        <KillSwitchControl />
      </Card>
    </Page>
  )
}
