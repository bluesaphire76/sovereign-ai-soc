import Link from "next/link";
import { ArrowUpRight, Database, Library } from "lucide-react";

import {
  isSafeInternalAssistantUrl,
  type AssistantAuthority,
  type AssistantSource,
} from "@/lib/assistant";
import {
  formatAssistantScore,
  humanizeAssistantValue,
  sourceAnchorId,
} from "./assistantPresentation";

type AssistantSourcesProps = {
  sources: AssistantSource[];
  anchorPrefix: string;
};

function SourceGroup({
  authority,
  sources,
  anchorPrefix,
  sourceIndexes,
}: {
  authority: AssistantAuthority;
  sources: AssistantSource[];
  anchorPrefix: string;
  sourceIndexes: Map<string, number>;
}) {
  const authoritative = authority === "authoritative";
  const Icon = authoritative ? Database : Library;

  if (sources.length === 0) return null;

  return (
    <section aria-labelledby={`${anchorPrefix}-${authority}-heading`}>
      <div className="mb-2 flex items-center gap-2">
        <Icon
          aria-hidden="true"
          className={`h-4 w-4 ${authoritative ? "text-emerald-300" : "text-amber-300"}`}
        />
        <h4
          id={`${anchorPrefix}-${authority}-heading`}
          className="text-xs font-semibold text-slate-200"
        >
          {authoritative ? "Authoritative sources" : "Advisory semantic sources"}
        </h4>
        <span className="text-[11px] text-slate-500">{sources.length}</span>
      </div>

      <ul className="grid gap-2 xl:grid-cols-2">
        {sources.map((source) => {
          const sourceIndex = sourceIndexes.get(source.source_id) ?? 0;
          const score = formatAssistantScore(source.score);

          return (
            <li
              key={`${source.source_id}-${source.source_type}-${source.record_id ?? ""}-${sourceIndex}`}
              id={sourceAnchorId(anchorPrefix, sourceIndex)}
              tabIndex={-1}
              className="min-w-0 border border-slate-800 bg-slate-950 p-3 outline-none focus:border-cyan-700"
            >
              <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`text-[10px] font-semibold ${
                        authoritative ? "text-emerald-300" : "text-amber-300"
                      }`}
                    >
                      {authoritative ? "AUTHORITATIVE" : "ADVISORY"}
                    </span>
                    <span className="text-[10px] font-semibold text-cyan-300">
                      [{source.source_id}]
                    </span>
                    <span className="text-[10px] text-slate-500">
                      {humanizeAssistantValue(source.source_type)}
                    </span>
                  </div>
                  <p className="mt-1 break-words text-xs font-medium leading-5 text-slate-100">
                    {source.label}
                  </p>
                </div>

                {isSafeInternalAssistantUrl(source.url) ? (
                  <Link
                    href={source.url}
                    className="inline-flex min-h-8 shrink-0 items-center gap-1.5 text-xs font-medium text-cyan-300 hover:text-cyan-200"
                    aria-label={`Open source ${source.source_id}: ${source.label}`}
                  >
                    Open source
                    <ArrowUpRight aria-hidden="true" className="h-3.5 w-3.5" />
                  </Link>
                ) : null}
              </div>

              <dl className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-500">
                {source.record_id ? (
                  <div className="flex gap-1">
                    <dt>Record</dt>
                    <dd className="break-all text-slate-300">{source.record_id}</dd>
                  </div>
                ) : null}
                {source.section ? (
                  <div className="flex min-w-0 gap-1">
                    <dt>Section</dt>
                    <dd className="break-words text-slate-300">{source.section}</dd>
                  </div>
                ) : null}
                {score ? (
                  <div className="flex gap-1">
                    <dt>Similarity</dt>
                    <dd className="text-slate-300">{score}</dd>
                  </div>
                ) : null}
              </dl>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

export default function AssistantSources({
  sources,
  anchorPrefix,
}: AssistantSourcesProps) {
  if (sources.length === 0) {
    return (
      <div className="border-t border-slate-800 pt-3 text-xs leading-5 text-slate-500">
        No supporting source records were returned for this answer.
      </div>
    );
  }

  const sourceIndexes = new Map(
    sources.map((source, index) => [source.source_id, index] as const),
  );
  const authoritative = sources.filter(
    (source) => source.authority === "authoritative",
  );
  const advisory = sources.filter((source) => source.authority === "advisory");

  return (
    <div className="space-y-4">
      <SourceGroup
        authority="authoritative"
        sources={authoritative}
        anchorPrefix={anchorPrefix}
        sourceIndexes={sourceIndexes}
      />
      <SourceGroup
        authority="advisory"
        sources={advisory}
        anchorPrefix={anchorPrefix}
        sourceIndexes={sourceIndexes}
      />
      {advisory.length > 0 ? (
        <p className="text-[11px] leading-5 text-amber-200">
          Semantic similarity is advisory and does not prove duplicate identity,
          causality, root cause, severity, or closure readiness.
        </p>
      ) : null}
    </div>
  );
}
