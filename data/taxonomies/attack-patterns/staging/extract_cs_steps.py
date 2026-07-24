#!/usr/bin/env python3
import yaml
import sys

# Read ATLAS YAML
with open('/Users/hjrnunes/workspace/hjrnunes/scenario-forge/data/taxonomies/atlas/ATLAS-2026.05.yaml') as f:
    data = yaml.safe_load(f)

case_studies = ['AML.CS0040', 'AML.CS0009', 'AML.CS0024', 'AML.CS0020', 'AML.CS0021', 'AML.CS0029', 'AML.CS0026']

for cs in case_studies:
    print(f"\n{'='*80}")
    print(f"{cs}: {data.get(cs, {}).get('name', 'NOT FOUND')}")
    print(f"{'='*80}")
    
    if cs not in data.get('relationships', {}):
        print(f"No relationships found for {cs}")
        continue
        
    employs = data['relationships'][cs].get('employs', [])
    
    # Sort by step-id
    employs_sorted = sorted(employs, key=lambda x: x.get('step-id', ''))
    
    print(f"\n{'Step':<6} {'Technique':<18} {'Tactic':<16} {'Description'}")
    print('-' * 120)
    
    for rel in employs_sorted:
        step_id = rel.get('step-id', 'N/A')
        tech = rel.get('target', 'N/A')
        tactic = rel.get('tactic', 'N/A')
        desc = rel.get('description', 'N/A')[:80]
        print(f"{step_id:<6} {tech:<18} {tactic:<16} {desc}")
