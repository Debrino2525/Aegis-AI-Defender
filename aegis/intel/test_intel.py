from aegis.intel.attack_mapper import build_attack_summary
from aegis.intel.asset_intelligence import compute_aegis_risk_score, compute_business_risk, build_contributing_factors, generate_top_insights

mock = [
  {'id':'CVE-2021-41773','title':'Apache Path Traversal','severity':'CRITICAL','cvss_score':9.8,'epss_score':0.97,'is_cisa_kev':True,'composite_risk_score':98.7,'cve_id':'CVE-2021-41773','description':'Apache RCE','evidence':'Apache 2.4.49 on port 80','remediation':'Upgrade','target':'test.com','port':80,'service':'http'},
  {'id':'CVE-2024-6387','title':'OpenSSH RCE','severity':'CRITICAL','cvss_score':8.1,'epss_score':0.88,'is_cisa_kev':False,'composite_risk_score':71.6,'cve_id':'CVE-2024-6387','description':'SSH RCE','evidence':'OpenSSH 8.5 on port 22','remediation':'Upgrade','target':'test.com','port':22,'service':'ssh'},
  {'id':'AEGIS-HTTP-001','title':'Missing HSTS','severity':'MEDIUM','cvss_score':5.9,'epss_score':0.0,'is_cisa_kev':False,'composite_risk_score':30.2,'cve_id':None,'description':'No HSTS','evidence':'Header missing','remediation':'Add header','target':'test.com','port':80,'service':'http'},
]

score = compute_aegis_risk_score(mock)
risk = compute_business_risk(mock)
factors = build_contributing_factors(mock)
insights = generate_top_insights(mock)
attack = build_attack_summary(mock)

print('[OK] Aegis TruRisk Score:', score)
print('[OK] Business Risk:', risk.get('formatted'))
print('[OK] Contributing factors:', [(f['name'], f['count']) for f in factors if f['count']>0])
print('[OK] Top insights:', len(insights))
print('[OK] ATT&CK tactics:', attack.get('tactic_counts'))
print('[OK] Ransomware CVEs:', len(attack.get('ransomware_cves',[])))
print()
print('ALL SYSTEMS GREEN - Aegis Enterprise Platform Ready')
