#!/usr/bin/python

from scapy.all import *
import numpy as np

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

p = rdpcap('syns.pcap')

sources = {}
with PcapReader('syns.pcap') as pr:
    for k in pr:
        try:
            # if SYN and not SACK
            if k['TCP'].flags & SYN and not k['TCP'].flags & ACK:
                if k['IP'].src not in sources.keys():
                    sources[k['IP'].src] = {}
                if k['IP'].dst not in sources[k['IP'].src].keys():
                    sources[k['IP'].src][k['IP'].dst] = {}
                    sources[k['IP'].src][k['IP'].dst]['times'] = []
                    sources[k['IP'].src][k['IP'].dst]['intervals'] = []
                # record when the connection occured
                sources[k['IP'].src][k['IP'].dst]['times'].append(k.time)
        except:
            continue
        
results = {}
for k in sources.keys():
    for d in sources[k].keys():
        #sort all the connection times
	sources[k][d]['times'].sort()
	last = sources[k][d]['times'][0]
	for t in sources[k][d]['times'][1:]:
            #calculate the length of time since the last connection
            sources[k][d]['intervals'].append(t - last)
            last = t
        # if there have been at least 3 connections, and the mean interval is at least 2 seconds
        if len(sources[k][d]['times']) > 2 and np.mean(sources[k][d]['intervals']) > 2:
           # calculate and save the mean interval and std-deviation of the intervals
           sources[k][d]['mean'] = np.mean(sources[k][d]['intervals'])
           sources[k][d]['std'] = np.std(sources[k][d]['intervals'])
           results[k + ' -> ' + d] = {'mean': sources[k][d]['mean'], 'std': sources[k][d]['std'], 'sessions': len(sources[k][d]['times'])}

results_by_std = sorted(results, key=lambda k: results[k]['std'])

for r in results_by_std:
    print r, results[r]['std'], results[r]['mean'], results[r]['sessions']



'''
s = p.sessions()
sources = {}
for k in s.keys():
    if s[k][0]['IP'].src not in sources.keys():
        sources[s[k][0]['IP'].src] = {}
    if s[k][0]['IP'].dst not in sources[s[k][0]['IP'].src].keys():
        sources[s[k][0]['IP'].src][s[k][0]['IP'].dst] = {}
        sources[s[k][0]['IP'].src][s[k][0]['IP'].dst]['times'] = []
        sources[s[k][0]['IP'].src][s[k][0]['IP'].dst]['intervals'] = []
    sources[s[k][0]['IP'].src][s[k][0]['IP'].dst]['times'].append(s[k][0].time)
'''
