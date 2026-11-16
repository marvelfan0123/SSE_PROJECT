"""Reproducible, dependency-free diagnostics for the experimental VulnX model.

Controlled cases are NOT real-world predictive validation. No CVE labels are invented.
"""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from risk_model import score_assessment_finding, image_risk

CASES = [
    {'id':'critical-no-intelligence','cvss':9.8,'epss_percentile':None,'kev_status':'unavailable'},
    {'id':'critical-low-threat','cvss':9.8,'epss_percentile':0.01,'kev_status':'not_listed'},
    {'id':'high-known-exploited','cvss':7.5,'epss_percentile':0.80,'kev_status':'listed'},
    {'id':'medium-high-threat','cvss':5.5,'epss_percentile':0.95,'kev_status':'not_listed'},
    {'id':'high-kev-no-epss','cvss':8.0,'epss_percentile':None,'kev_status':'listed'},
    {'id':'high-epss-no-kev','cvss':8.0,'epss_percentile':0.95,'kev_status':'unavailable'},
    {'id':'low-low-threat','cvss':2.5,'epss_percentile':0.01,'kev_status':'not_listed'},
    {'id':'zero-severity','cvss':0.0,'epss_percentile':0.0,'kev_status':'not_listed'},
]

def evaluate_cases(cases=CASES):
    rows=[]
    for c in cases:
        finding={'source':'Trivy','cvss':c['cvss'],'epss_percentile':c.get('epss_percentile'),
                 'kev_status':c.get('kev_status','unavailable')}
        r=score_assessment_finding(finding,None,1)
        rows.append({'case':c['id'],'base':r['base_risk'],'threat':r['threat_priority'],
                     'contextual':r['contextual_risk'],'priority':r['risk_label'],
                     'confidence':r['scoring_confidence'],'threat_model':r['threat_model']})
    by={r['case']:r for r in rows}
    diagnostics={
        'severity_floor_preserved':by['critical-low-threat']['threat'] >= by['critical-no-intelligence']['threat'],
        'kev_partial_enrichment_preserved':by['high-kev-no-epss']['threat'] > by['high-kev-no-epss']['base'],
        'epss_partial_enrichment_preserved':by['high-epss-no-kev']['threat'] > by['high-epss-no-kev']['base'],
        'kev_priority_floor':by['high-known-exploited']['priority'] in ('High','Critical'),
        'unknown_exposure_numeric_score':all(r['contextual'] is not None for r in rows),
        'score_bounded':all(0 <= r['threat'] <= 100 and 0 <= r['contextual'] <= 100 for r in rows),
    }
    sample={'asset':'benchmark-image','cve':'CVE-EXAMPLE-0001','package':'libx','threat_priority':80}
    diagnostics['image_deduplication']=image_risk([sample,sample]) == image_risk([sample])
    return {'dataset':'controlled hypothetical scenarios (NOT actual CVEs)', 'case_count':len(rows),
            'rows':rows,'diagnostics':diagnostics}

def evaluate_labeled_csv(path):
    """Optional real-data ranking evaluation. Requires independently obtained labels.

    Columns: cve, cvss, epss_percentile, kev_status, exploited_label.
    exploited_label must come from independent later observation; KEV-derived labels
    would leak the KEV input into the evaluation target.
    """
    with open(path,newline='',encoding='utf-8') as f:
        records=list(csv.DictReader(f))
    required={'cve','cvss','epss_percentile','kev_status','exploited_label'}
    if not records or not required.issubset(records[0]):
        raise ValueError('CSV must have rows and columns: '+', '.join(sorted(required)))
    samples=[]
    for row in records:
        label=int(row['exploited_label'])
        if label not in (0,1): raise ValueError('exploited_label must be 0 or 1')
        p=float(row['epss_percentile']) if row['epss_percentile'].strip() else None
        score=score_assessment_finding({'source':'Trivy','cvss':float(row['cvss']),
               'epss_percentile':p,'kev_status':row['kev_status']},None,1)
        samples.append((label,score['base_risk'],score['threat_priority']))
    def ranking(scores):
        # Pairwise AUC: rank exploited above non-exploited, ties worth half.
        positives=[s for y,s in scores if y==1]; negatives=[s for y,s in scores if y==0]
        if not positives or not negatives: return None
        return round(sum((a>b)+.5*(a==b) for a in positives for b in negatives)/(len(positives)*len(negatives)),4)
    return {'dataset':str(path),'samples':len(samples),'positives':sum(y for y,_,_ in samples),
            'base_auc':ranking([(y,b) for y,b,_ in samples]),
            'threat_auc':ranking([(y,t) for y,_,t in samples]),
            'warning':'Only valid if labels are independent and temporally later than all input data; otherwise label leakage.'}

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--labeled-csv',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=evaluate_labeled_csv(args.labeled_csv) if args.labeled_csv else evaluate_cases()
    output=json.dumps(result,indent=2)
    if args.output: args.output.write_text(output+'\n',encoding='utf-8')
    print(output)
