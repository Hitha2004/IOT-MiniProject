#!/usr/bin/env python3
"""
NS-3 RPL DAO Attack Analysis - Research Paper Style Graphs
Generates graphs similar to the reference IEEE paper
"""

import subprocess
import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# Configuration
NS3_PATH = "/home/sandeep-1/ns-allinone-3.45/ns-3.45"
SCRATCH_PATH = os.path.join(NS3_PATH, "scratch")
RESULTS_DIR = os.path.join(NS3_PATH, "paper_graphs")

# Create results directory
os.makedirs(RESULTS_DIR, exist_ok=True)

# Verify paths exist
if not os.path.exists(NS3_PATH):
    print(f"❌ ERROR: NS-3 path not found: {NS3_PATH}")
    exit(1)
if not os.path.exists(SCRATCH_PATH):
    print(f"❌ ERROR: Scratch folder not found: {SCRATCH_PATH}")
    exit(1)

def run_simulation(attack, attacker_pps=800, threshold=20, n_nodes=25, window=1.0, sim_time=120):
    """Run a single NS-3 simulation and return results"""
    if attack:
        cmd = (
            f"./ns3 run 'ns3_rpl_dao_mitigation "
            f"--attack=true --attackerPps={attacker_pps} --attackerPkt=120 "
            f"--threshold={threshold} --windowSec={window} --nNodes={n_nodes} "
            f"--area=60 --rateKbps=16 --simTime={sim_time}'"
        )
    else:
        cmd = (
            f"./ns3 run 'ns3_rpl_dao_mitigation "
            f"--attack=false --nNodes={n_nodes} --area=60 "
            f"--rateKbps=16 --simTime={sim_time}'"
        )
    
    result = subprocess.run(cmd, shell=True, cwd=NS3_PATH, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"   ❌ Failed!")
        return None
    
    try:
        pdr = pd.read_csv(f"{NS3_PATH}/results/run1_pdr.csv")
        delay = pd.read_csv(f"{NS3_PATH}/results/run1_delay.csv")
        overhead = pd.read_csv(f"{NS3_PATH}/results/run1_overhead.csv")
        
        return {
            'pdr': pdr['pdr'].values[0],
            'tx': pdr['tx'].values[0],
            'rx': pdr['rx'].values[0],
            'delay_ms': delay['avg_delay_s'].values[0] * 1000,
            'ctrl_tx': overhead['control_tx'].values[0],
            'ctrl_rx': overhead['control_rx'].values[0],
            'ctrl_dropped': overhead['control_dropped'].values[0],
        }
    except Exception as e:
        print(f"   ❌ Error reading results: {e}")
        return None

def collect_baseline_data():
    """Collect baseline scenarios (RPL, InsecRPL, SecRPL)"""
    print("\n" + "="*70)
    print("COLLECTING BASELINE DATA")
    print("="*70)
    
    scenarios = []
    
    # RPL (No Attack)
    print("▶ RPL (No Attack)...")
    result = run_simulation(attack=False)
    if result:
        result['scenario'] = 'RPL'
        scenarios.append(result)
        print(f"   ✓ PDR: {result['pdr']:.3f}")
    
    # InsecRPL (Attack Only)
    print("▶ InsecRPL (Attack Only)...")
    result = run_simulation(attack=True, threshold=1000000000)
    if result:
        result['scenario'] = 'InsecRPL'
        scenarios.append(result)
        print(f"   ✓ PDR: {result['pdr']:.3f}")
    
    # SecRPL (Attack + Mitigation)
    print("▶ SecRPL (Attack + Mitigation)...")
    result = run_simulation(attack=True, threshold=20)
    if result:
        result['scenario'] = 'SecRPL'
        scenarios.append(result)
        print(f"   ✓ PDR: {result['pdr']:.3f}")
    
    return pd.DataFrame(scenarios)

def collect_attack_frequency_data():
    """Vary attack frequency (attacker PPS)"""
    print("\n" + "="*70)
    print("COLLECTING ATTACK FREQUENCY DATA")
    print("="*70)
    
    # Attack frequencies in packets per second (similar to paper's intervals)
    frequencies = [200, 400, 600, 800, 1000]
    
    all_data = []
    for pps in frequencies:
        print(f"▶ Testing attack frequency: {pps} pps...")
        
        # InsecRPL
        result = run_simulation(attack=True, attacker_pps=pps, threshold=1000000000)
        if result:
            result['scenario'] = 'InsecRPL'
            result['attack_pps'] = pps
            all_data.append(result)
        
        # SecRPL
        result = run_simulation(attack=True, attacker_pps=pps, threshold=20)
        if result:
            result['scenario'] = 'SecRPL'
            result['attack_pps'] = pps
            all_data.append(result)
        
        print(f"   ✓ Completed")
    
    # Add RPL baseline for all frequencies
    result = run_simulation(attack=False)
    if result:
        for pps in frequencies:
            r = result.copy()
            r['scenario'] = 'RPL'
            r['attack_pps'] = pps
            all_data.append(r)
    
    return pd.DataFrame(all_data)

def collect_threshold_data():
    """Vary mitigation threshold (DAOMax)"""
    print("\n" + "="*70)
    print("COLLECTING THRESHOLD DATA")
    print("="*70)
    
    thresholds = [5, 10, 20, 30, 50]
    
    all_data = []
    for thresh in thresholds:
        print(f"▶ Testing threshold: {thresh}...")
        
        result = run_simulation(attack=True, attacker_pps=800, threshold=thresh)
        if result:
            result['scenario'] = 'SecRPL'
            result['threshold'] = thresh
            all_data.append(result)
            print(f"   ✓ PDR: {result['pdr']:.3f}")
    
    return pd.DataFrame(all_data)

def create_research_style_graphs(baseline_df, freq_df, thresh_df):
    """Create publication-quality graphs matching the research paper style"""
    
    # Set publication style
    plt.rcParams['font.family'] = 'serif'
    plt.rcParams['font.size'] = 11
    plt.rcParams['axes.labelsize'] = 12
    plt.rcParams['axes.titlesize'] = 13
    plt.rcParams['xtick.labelsize'] = 11
    plt.rcParams['ytick.labelsize'] = 11
    plt.rcParams['legend.fontsize'] = 10
    plt.rcParams['figure.titlesize'] = 14
    
    # Color scheme matching paper
    colors = {
        'RPL': '#1f77b4',      # Blue
        'InsecRPL': '#ff7f0e',  # Orange  
        'SecRPL': '#2ca02c',    # Green
    }
    
    markers = {
        'RPL': 'o',
        'InsecRPL': 's',
        'SecRPL': '^',
    }
    
    # ============= GRAPH 1: Control Overhead vs Attack Frequency =============
    if not freq_df.empty:
        fig, ax = plt.subplots(figsize=(8, 5))
        
        for scenario in ['RPL', 'InsecRPL', 'SecRPL']:
            data = freq_df[freq_df['scenario'] == scenario].sort_values('attack_pps')
            if not data.empty:
                # Convert PPS to seconds for x-axis (similar to paper)
                x_vals = 1.0 / data['attack_pps'].values  # Frequency in seconds
                y_vals = data['ctrl_rx'].values  # Convert to numpy array
                ax.plot(x_vals, y_vals, 
                       marker=markers[scenario], linewidth=2, markersize=8,
                       label=scenario, color=colors[scenario])
        
        ax.set_xlabel('Frequency of DAO Attack (seconds)', fontweight='bold')
        ax.set_ylabel('Number of DAO Forwarded', fontweight='bold')
        ax.set_title('Control Overhead vs Attack Intervals', fontweight='bold')
        ax.legend(loc='best', frameon=True, shadow=True)
        ax.grid(True, alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(f'{RESULTS_DIR}/figure1_dao_overhead.png', dpi=300, bbox_inches='tight')
        print("✓ Saved: figure1_dao_overhead.png")
        plt.close()
    
    # ============= GRAPH 2: Downward PDR vs Attack Frequency =============
    if not freq_df.empty:
        fig, ax = plt.subplots(figsize=(8, 5))
        
        for scenario in ['RPL', 'InsecRPL', 'SecRPL']:
            data = freq_df[freq_df['scenario'] == scenario].sort_values('attack_pps')
            if not data.empty:
                x_vals = 1.0 / data['attack_pps'].values
                y_vals = data['pdr'].values
                ax.plot(x_vals, y_vals, 
                       marker=markers[scenario], linewidth=2, markersize=8,
                       label=scenario, color=colors[scenario])
        
        ax.set_xlabel('Frequency of DAO Attack (seconds)', fontweight='bold')
        ax.set_ylabel('Downward PDR', fontweight='bold')
        ax.set_title('Packet Delivery Ratio vs Attack Intervals', fontweight='bold')
        ax.set_ylim([0.7, 1.0])
        ax.legend(loc='best', frameon=True, shadow=True)
        ax.grid(True, alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(f'{RESULTS_DIR}/figure2_pdr_vs_frequency.png', dpi=300, bbox_inches='tight')
        print("✓ Saved: figure2_pdr_vs_frequency.png")
        plt.close()
    
    # ============= GRAPH 3: Delay vs Attack Frequency =============
    if not freq_df.empty:
        fig, ax = plt.subplots(figsize=(8, 5))
        
        for scenario in ['RPL', 'InsecRPL', 'SecRPL']:
            data = freq_df[freq_df['scenario'] == scenario].sort_values('attack_pps')
            if not data.empty:
                x_vals = 1.0 / data['attack_pps'].values
                y_vals = data['delay_ms'].values
                ax.plot(x_vals, y_vals, 
                       marker=markers[scenario], linewidth=2, markersize=8,
                       label=scenario, color=colors[scenario])
        
        ax.set_xlabel('Frequency of DAO Attack (seconds)', fontweight='bold')
        ax.set_ylabel('Downward Latency (ms)', fontweight='bold')
        ax.set_title('End-to-End Delay vs Attack Intervals', fontweight='bold')
        ax.legend(loc='best', frameon=True, shadow=True)
        ax.grid(True, alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(f'{RESULTS_DIR}/figure3_delay_vs_frequency.png', dpi=300, bbox_inches='tight')
        print("✓ Saved: figure3_delay_vs_frequency.png")
        plt.close()
    
    # ============= GRAPH 4: PDR vs Threshold (DAOMax) =============
    if not thresh_df.empty:
        fig, ax = plt.subplots(figsize=(8, 5))
        
        data = thresh_df.sort_values('threshold')
        x_vals = data['threshold'].values
        y_vals = data['pdr'].values
        ax.plot(x_vals, y_vals, 
               marker='^', linewidth=2, markersize=8,
               label='SecRPL', color=colors['SecRPL'])
        
        # Add baseline if available
        if not baseline_df.empty:
            rpl_pdr = baseline_df[baseline_df['scenario'] == 'RPL']['pdr'].values[0]
            ax.axhline(y=rpl_pdr, color=colors['RPL'], linestyle='--', 
                      linewidth=2, label='RPL (Baseline)')
            
            insec_pdr = baseline_df[baseline_df['scenario'] == 'InsecRPL']['pdr'].values[0]
            ax.axhline(y=insec_pdr, color=colors['InsecRPL'], linestyle='--', 
                      linewidth=2, label='InsecRPL')
        
        ax.set_xlabel('DAO Threshold Max', fontweight='bold')
        ax.set_ylabel('Downward PDR', fontweight='bold')
        ax.set_title('PDR under various DAO Threshold', fontweight='bold')
        ax.set_ylim([0.8, 1.0])
        ax.legend(loc='best', frameon=True, shadow=True)
        ax.grid(True, alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(f'{RESULTS_DIR}/figure4_pdr_vs_threshold.png', dpi=300, bbox_inches='tight')
        print("✓ Saved: figure4_pdr_vs_threshold.png")
        plt.close()
    
    # ============= GRAPH 5: Control Overhead vs Threshold =============
    if not thresh_df.empty:
        fig, ax = plt.subplots(figsize=(8, 5))
        
        data = thresh_df.sort_values('threshold')
        x_vals = data['threshold'].values
        y_vals = data['ctrl_rx'].values
        ax.plot(x_vals, y_vals, 
               marker='^', linewidth=2, markersize=8,
               label='SecRPL', color=colors['SecRPL'])
        
        ax.set_xlabel('DAO Threshold Max', fontweight='bold')
        ax.set_ylabel('Number of DAO Forwarded', fontweight='bold')
        ax.set_title('Control Overhead under various DAO Threshold', fontweight='bold')
        ax.legend(loc='best', frameon=True, shadow=True)
        ax.grid(True, alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(f'{RESULTS_DIR}/figure5_overhead_vs_threshold.png', dpi=300, bbox_inches='tight')
        print("✓ Saved: figure5_overhead_vs_threshold.png")
        plt.close()
    
    # ============= GRAPH 6: Comparative Bar Chart =============
    if not baseline_df.empty:
        fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 5))
        
        scenarios = baseline_df['scenario'].values
        pdr_vals = baseline_df['pdr'].values
        delay_vals = baseline_df['delay_ms'].values
        ctrl_vals = baseline_df['ctrl_rx'].values
        
        # PDR
        bars1 = ax1.bar(scenarios, pdr_vals, 
                       color=[colors[s] for s in scenarios], edgecolor='black', linewidth=1.5)
        ax1.set_ylabel('PDR', fontweight='bold')
        ax1.set_title('Packet Delivery Ratio', fontweight='bold')
        ax1.set_ylim([0, 1.1])
        ax1.grid(axis='y', alpha=0.3)
        for i, bar in enumerate(bars1):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{pdr_vals[i]:.3f}', ha='center', va='bottom', fontsize=10, fontweight='bold')
        
        # Delay
        bars2 = ax2.bar(scenarios, delay_vals, 
                       color=[colors[s] for s in scenarios], edgecolor='black', linewidth=1.5)
        ax2.set_ylabel('Delay (ms)', fontweight='bold')
        ax2.set_title('End-to-End Delay', fontweight='bold')
        ax2.grid(axis='y', alpha=0.3)
        for i, bar in enumerate(bars2):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{delay_vals[i]:.1f}', ha='center', va='bottom', fontsize=10, fontweight='bold')
        
        # Control Overhead
        bars3 = ax3.bar(scenarios, ctrl_vals, 
                       color=[colors[s] for s in scenarios], edgecolor='black', linewidth=1.5)
        ax3.set_ylabel('Control Packets', fontweight='bold')
        ax3.set_title('Control Traffic Overhead', fontweight='bold')
        ax3.grid(axis='y', alpha=0.3)
        for i, bar in enumerate(bars3):
            height = bar.get_height()
            ax3.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(ctrl_vals[i])}', ha='center', va='bottom', fontsize=10, fontweight='bold')
        
        plt.suptitle('Performance Comparison: RPL vs InsecRPL vs SecRPL', 
                    fontsize=14, fontweight='bold', y=1.02)
        plt.tight_layout()
        plt.savefig(f'{RESULTS_DIR}/figure6_comparison.png', dpi=300, bbox_inches='tight')
        print("✓ Saved: figure6_comparison.png")
        plt.close()

def print_summary_table(baseline_df, freq_df, thresh_df):
    """Print summary statistics"""
    print("\n" + "="*80)
    print("SUMMARY STATISTICS")
    print("="*80)
    
    if not baseline_df.empty:
        print("\n📊 Baseline Scenarios:")
        print(baseline_df[['scenario', 'pdr', 'delay_ms', 'ctrl_rx', 'ctrl_dropped']].to_string(index=False))
        
        if 'InsecRPL' in baseline_df['scenario'].values and 'SecRPL' in baseline_df['scenario'].values:
            insec_pdr = baseline_df[baseline_df['scenario'] == 'InsecRPL']['pdr'].values[0]
            sec_pdr = baseline_df[baseline_df['scenario'] == 'SecRPL']['pdr'].values[0]
            improvement = ((sec_pdr - insec_pdr) / insec_pdr) * 100
            
            print(f"\n✨ Key Findings:")
            print(f"   • Mitigation PDR Improvement: {improvement:.2f}%")
            print(f"   • Attack Impact (PDR Drop): {(1 - insec_pdr) * 100:.2f}%")
            
            blocked = baseline_df[baseline_df['scenario'] == 'SecRPL']['ctrl_dropped'].values[0]
            print(f"   • Malicious Packets Blocked: {int(blocked)}")

def main():
    print("\n" + "🚀 " + "="*76 + " 🚀")
    print("   NS-3 RPL DAO ATTACK ANALYSIS - RESEARCH PAPER STYLE")
    print("🚀 " + "="*76 + " 🚀\n")
    
    # Verify paths
    print(f"📁 NS-3 Path: {NS3_PATH}")
    print(f"📁 Scratch Path: {SCRATCH_PATH}")
    print(f"📁 Results Directory: {RESULTS_DIR}")
    
    # Check if code exists in scratch
    code_file = os.path.join(SCRATCH_PATH, "ns3_rpl_dao_mitigation.cc")
    if not os.path.exists(code_file):
        print(f"\n❌ ERROR: Code file not found!")
        print(f"   Expected: {code_file}")
        print("   Please ensure ns3_rpl_dao_mitigation.cc is in the scratch folder")
        return
    else:
        print(f"✅ Found code: {code_file}\n")
    
    # Collect all data
    baseline_df = collect_baseline_data()
    freq_df = collect_attack_frequency_data()
    thresh_df = collect_threshold_data()
    
    # Save raw data
    baseline_df.to_csv(f'{RESULTS_DIR}/baseline_data.csv', index=False)
    freq_df.to_csv(f'{RESULTS_DIR}/frequency_data.csv', index=False)
    thresh_df.to_csv(f'{RESULTS_DIR}/threshold_data.csv', index=False)
    print(f"\n💾 Saved raw data to {RESULTS_DIR}/")
    
    # Generate graphs
    print("\n📊 Generating publication-quality graphs...")
    create_research_style_graphs(baseline_df, freq_df, thresh_df)
    
    # Print summary
    print_summary_table(baseline_df, freq_df, thresh_df)
    
    print("\n" + "✅ " + "="*76 + " ✅")
    print(f"   ANALYSIS COMPLETE! Generated 6 figures in {RESULTS_DIR}/")
    print("✅ " + "="*76 + " ✅\n")
    
    print("📈 Generated Figures:")
    print("   1. figure1_dao_overhead.png - Control overhead vs attack frequency")
    print("   2. figure2_pdr_vs_frequency.png - PDR vs attack frequency")
    print("   3. figure3_delay_vs_frequency.png - Delay vs attack frequency")
    print("   4. figure4_pdr_vs_threshold.png - PDR vs threshold parameter")
    print("   5. figure5_overhead_vs_threshold.png - Overhead vs threshold")
    print("   6. figure6_comparison.png - Overall performance comparison\n")

if __name__ == "__main__":
    main()
