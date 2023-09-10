import pyshark
from decrypt import time_quic_decrypt_initial
import numpy as np
import argparse
from hwcounter import Timer

def main(pcap_file):
    pcap_data = pyshark.FileCapture(pcap_file)
    cycles = []
    cycles_total = []
    for packet in pcap_data:
        with Timer() as t:
            if "quic" in packet:
                clock_cyles = time_quic_decrypt_initial(packet)
                if clock_cyles is not None:
                    cycles.append(clock_cyles)
                else:
                    continue
        cycles_total.append(t.cycles)

    arr = np.array(cycles[1:])
    avg = np.mean(arr)
    std = np.std(arr)

    print(f'Clock Cycles: {avg} ± {std}')

    with open("cycles.txt", "w") as f:
        for i in cycles:
            f.write(str(i) + "\n")

    arr = np.array(cycles_total[1:])
    avg = np.mean(arr)
    std = np.std(arr)

    with open("cycles_total.txt", "w") as f:
        for i in cycles_total:
            f.write(str(i) + "\n")

    print(f'Total Clock Cycles: {avg} ± {std}')



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help = "Pcap file to be analyzed")
    args = parser.parse_args()
    pcap_file = args.file
    main(pcap_file)
