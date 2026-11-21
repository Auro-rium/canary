import { Link, useParams } from 'react-router-dom'
import { Card, Metric, Page, PageHeader } from '../components/layout'
import { ResultsTable } from '../components/ResultsTable'
import { ErrorState, SkeletonList, StatusBadge, buttonClass } from '../components/ui'
import { getCampaign, reportUrl } from '../lib/api'
import { isCampaignTerminal } from '../lib/liveState'
import { percent } from '../lib/presentation'
import { useLoad } from '../lib/useLoad'

/** Per-technique attack success rate with confidence intervals. Reuses GET /campaigns/{id}; nothing new on the backend. */
export default function ResultsPage() {
  const { campaignId = '' } = useParams()
  const { data, error, loading, reload } = useLoad(() => getCampaign(campaignId), campaignId)
  const finished = data ? isCampaignTerminal(data.status) : false
  const trials = data?.technique_results.reduce((sum, r) => sum + r.trials, 0) ?? 0
  const confirmed = data?.technique_results.reduce((sum, r) => sum + r.confirmed, 0) ?? 0

  return (
    <Page>
      <PageHeader eyebrow="Campaign results" title={data?.target_name ?? 'Results'} description="Attack success rate per technique. The bar marks the rate and its 95% confidence interval: a wide band means few trials.">
        {data && <StatusBadge status={data.status} />}
        {data?.environment === 'production' && <StatusBadge status="production" />}
        <Link to={`/campaigns/${encodeURIComponent(campaignId)}`} className={buttonClass}>Live view</Link>
        <Link to={`/findings?campaign_id=${encodeURIComponent(campaignId)}`} className={buttonClass}>Findings</Link>
      </PageHeader>
      {error && <ErrorState title="Could not load results" message={error} onRetry={reload} />}
      {loading && !data && !error && <SkeletonList rows={4} label="Loading results" />}
      {data && (
        <div className="space-y-6">
          <div className="flex flex-wrap gap-3">
            <Metric label="Techniques" value={data.technique_results.length} />
            <Metric label="Trials scored" value={trials} />
            <Metric label="Confirmed" value={confirmed} tone={confirmed > 0 ? 'danger' : 'default'} />
            <Metric label="Overall success rate" value={trials > 0 ? percent(confirmed / trials) : '—'} />
          </div>
          {!finished && <p className="text-muted">This campaign is still {data.status}. Rates are final once it completes; follow it in the live view.</p>}
          <ResultsTable results={data.technique_results} />
          {finished && (
            <Card className="flex flex-wrap items-center gap-2">
              <h2 className="mr-2 text-base font-semibold">Download report</h2>
              {(['json', 'md', 'pdf'] as const).map(format => (
                <a key={format} href={reportUrl(campaignId, format)} className={buttonClass} aria-label={`Download ${format === 'md' ? 'Markdown' : format.toUpperCase()} report`}>{format === 'md' ? 'Markdown' : format.toUpperCase()}</a>
              ))}
            </Card>
          )}
        </div>
      )}
    </Page>
  )
}
