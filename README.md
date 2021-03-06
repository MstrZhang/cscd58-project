# Directory Structure
- put raw files in a directory called `/raw`
- put scripts in the `/scripts` directory
    - modify any locations as necessary
- cdf graphs are in `/cdf`

NOTE: `.gitignore` is ignoring the folder `/raw` so put large files in this folder otherwise GitHub will not let you upload

since the `/raw` directory is too large for MarkUs you can download it here
(https://drive.google.com/open?id=1W04gy6QXZYLK0XYyODGIUvHdD9XzdvuE)

---

# Getting Files
Add all of these files to `/raw` and change locations in scripts as necessary
- `univ1_trace.csv`
    - from wireshark:  `File > Export Packet Dissections > As CSV`
    - save file as `univ1_trace.csv`
- modified `...dump.csv`
    - from wireshark, right click on the columns tab
        - click `Configure Columns`
            - add  new columns as needed
            - Example:
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