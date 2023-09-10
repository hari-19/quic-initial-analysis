# quic-initial-analysis

Author: Hari Hara Sudhan

The dataset was created using the program in the dataset_creation folder. The `dataset_creation/browser.py` opens the browser and connects to various QUIC enabled webservers continuously. `dataset_creation/capture.py` sniffs all the packets and saves the Client Hello initial packet in a pcap file.

By doing so, we captured 5000 QUIC Initial packets while connecting to various webservers.

The main.py opens all the captured packets supplied via the pcap file with `-f` argument. It takes the payload of the QUIC initial packet and decrypts it as per `RFC 9001` guidelines.

The time taken to decrypt the payload vs the entire processing of the packet is measured using `hwcounter` package that uses an hardware counter to measure the clock cyles elapsed.