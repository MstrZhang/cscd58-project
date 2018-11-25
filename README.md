# Directory Structure
- put raw files in a directory called `/raw`
- put scripts in the `/scripts` directory
    - modify any locations as necessary
- put any references in `/resources`

NOTE: `.gitignore` is ignoring the folder `/raw` so put large files in this folder otherwise GitHub will not let you upload

---

# Getting Files
Add all of these files to `/raw` and change locations in scripts as necessary
- `univ1_trace.csv`
    - from wireshark:  `File > Export Packet Dissections > As CSV`
    - save file as `univ1_trace.csv`
- `new_dump.csv`
    - from wireshark, right click on the columns tab
        - click `Configure Columns`
            - add two new columns named `TCP Header` and `IP Header`
            - set the fields to be `tcp.hdr_len` and `ip.hdr_len` respectively
    - extract the `.csv` file the same way as above
- `univ1_pt5.pcap`
    - extract the original tar
    - take `univ1_pt5`
        - add extension if necessary
- `protocol_hierarchy.csv`
    - from wireshark: `Statistics > Protocol Hierarchy > Copy > As CSV`
        - this may be slow or take a while

---

# Additional Notes
- scripts must be run using Python 2.x
- matplotlib only plots one graph at a time
    - comment out the graphs you do not want to plot