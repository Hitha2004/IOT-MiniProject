🌍 RPL DAO Flooding Mitigation in IoT Networks

A lightweight and adaptive defense framework to safeguard RPL-based IoT systems from DAO flooding and replay attacks, designed and validated using NS-3 network simulator.
The approach combines sliding-window rate monitoring and adaptive rate limiting to prevent congestion before it occurs.

🧩 Abstract

Routing attacks pose a major challenge to IoT networks that rely on RPL (Routing Protocol for Low-Power and Lossy Networks).
Among these, DAO flooding attacks exploit the control-plane by sending excessive routing updates, overwhelming the network and degrading reliability.

This project presents a real-time mitigation scheme that detects abnormal DAO activity based on transmission frequency and dynamically limits offending sources.
It is designed to be lightweight, autonomous, and suitable for constrained IoT devices.

🔍 Objectives

Identify vulnerabilities in RPL’s DAO message handling

Design a non-cryptographic detection strategy based on rate observation

Implement a sliding-window threshold for attack detection

Apply adaptive suppression to malicious nodes

Validate through NS-3 simulation under multiple attack intensities

⚡ Highlights

🧠 Real-time rate analysis: Tracks DAO transmission behavior for every node

🔄 Self-adjusting control: Throttles malicious senders automatically

💡 Low overhead: Minimal memory and CPU footprint on low-power hardware

📊 Resilient performance: Restores over 80% of lost PDR during attacks

🌐 Cross-layer impact: Reduces congestion at the MAC layer, preventing packet loss

🔧 Easily tunable: Thresholds and windows adjustable for any IoT deployment

🚨 Problem Overview

In RPL networks, compromised nodes can repeatedly transmit DAO messages, leading to:

Network congestion and control overhead

Increased latency and packet drops

Energy depletion in constrained devices

Existing cryptographic protections fail to address this since attackers are often authenticated insiders.
Hence, a behavior-based detection mechanism is essential.

💡 Proposed Approach

The defense operates at the RPL root node, which monitors the rate of DAO messages per source within a short observation window.
When the message rate exceeds a defined threshold, the node is temporarily flagged, and its transmission rate is reduced.
If normal behavior resumes, it is automatically unblocked — ensuring no permanent penalties for transient bursts.

This proactive feedback mechanism prevents attack packets from consuming bandwidth, achieving prevention rather than post-attack filtering.

📈 Experimental Insights

Achieved ~99.5% packet delivery under protection, matching baseline performance

Reduced attack traffic by over 98%

Average latency remained within 6 ms, close to non-attack conditions

Detection response time: ≈25 ms, fast enough for real-time mitigation

The system consistently performed well across varying attack rates (200–1000 pps) and threshold values, confirming robustness and scalability.

🔬 Research Impact

This approach demonstrates how behavioral monitoring and adaptive rate control can secure IoT routing protocols without heavy cryptography.
It highlights the benefits of cross-layer coordination, where network-layer decisions proactively reduce MAC-layer congestion.

🚀 Future Scope

🕸️ Distributed detection across multiple parent nodes

🤖 Integration of ML-based adaptive thresholds

🔒 Combination with RPL secure mode for layered defense

🧱 Validation on real IoT testbeds (Contiki-NG, RIOT-OS)

📡 Evaluation under multi-attacker and cooperative flooding scenarios

🎓 Acknowledgment

Developed as part of research on IoT Network Security at
National Institute of Technology Karnataka (NITK).

Special thanks to the NS-3 Consortium for providing the simulation framework that made large-scale IoT experimentation feasible.
