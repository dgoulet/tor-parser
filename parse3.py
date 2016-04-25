import os, sys
import stem
import urllib.request
import time
import pygeoip
import tarfile
import shutil

from stem.descriptor import DocumentHandler, parse_file

GEOIP_FILENAME = "GeoLiteCity.dat"
geoip_db = None

def geo_ip_lookup(ip_address):
    record = geoip_db.record_by_addr(ip_address)
    if record is None:
        return (False, False)
    return (record['longitude'], record['latitude'])

def dl_server_descriptors(year, month):
    """ Download server descriptors from CollecTor. """
    url = "https://collector.torproject.org/archive/relay-descriptors/server-descriptors"
    filename = "server-descriptors-%s-%s.tar.xz" % (year, month)

    save_dir_path = "server-descriptors"
    if not os.path.isdir(save_dir_path):
        os.mkdir(save_dir_path)
    save_path = "%s/%s" % (save_dir_path, filename)
    if os.path.isfile(save_path):
        print("  [+] Server descriptors %s found" % (save_path))
        return save_path
    # Check if the directory exists.
    if os.path.isdir("%s" % (save_path[:-7])):
        print("  [+] Server descriptors %s found" % (save_path[:-7]))
        return save_path

    print("  [+] Downloading server descriptors %s/%s" % (url, filename))
    try:
        request = urllib.request.urlopen("%s/%s" % (url, filename))
        if request.code != 200:
            print("  [-] Unable to fetch server descriptors %s at %s" % \
                  (filename, url))
            return None
    except Exception as e:
        print("  [-] Unable to fetch %s/%s" % (url, filename))
        return None
    fp = open(save_path, "wb+")
    fp.write(request.read())
    fp.close()
    return save_path

def dl_consensus(year, month):
    """ Download consensus from CollecTor. """
    url = "https://collector.torproject.org/archive/relay-descriptors/consensuses"
    filename = "consensuses-%s-%s.tar.xz" % (year, month)

    save_dir_path = "consensuses"
    if not os.path.isdir(save_dir_path):
        os.mkdir(save_dir_path)
    save_path = "%s/%s" % (save_dir_path, filename)
    if os.path.isfile(save_path):
        print("  [+] Consensus %s found" % (save_path))
        return save_path
    # Check if the directory exists.
    if os.path.isdir("%s" % (save_path[:-7])):
        print("  [+] Consensus %s found" % (save_path[:-7]))
        return save_path

    print("  [+] Downloading consensus %s/%s" % (url, filename))
    try:
        request = urllib.request.urlopen("%s/%s" % (url, filename))
        if request.code != 200:
            print("  [-] Unable to fetch consensus %s at %s" % (filename, url))
            return None
    except Exception as e:
        print("  [-] Unable to fetch %s/%s" % (url, filename))
        return None

    fp = open(save_path, "wb+")
    fp.write(request.read())
    fp.close()
    return save_path

def dl_extra_infos(year, month):
    """ Download extra infos from CollecTor. """
    url = "https://collector.torproject.org/archive/relay-descriptors/extra-infos"
    filename = "extra-infos-%s-%s.tar.xz" % (year, month)

    save_dir_path = "extra-infos"
    if not os.path.isdir(save_dir_path):
        os.mkdir(save_dir_path)
    save_path = "%s/%s" % (save_dir_path, filename)
    if os.path.isfile(save_path):
        print("  [+] Extra infos %s found" % (save_path))
        return save_path
    # Check if the directory exists.
    if os.path.isdir("%s" % (save_path[:-7])):
        print("  [+] Extra infos %s found" % (save_path[:-7]))
        return save_path

    print("  [+] Downloading extra infos %s/%s" % (url, filename))
    try:
        request = urllib.request.urlopen("%s/%s" % (url, filename))
        if request.code != 200:
            print("  [-] Unable to fetch extra infos %s at %s" % (filename, url))
            return None
    except Exception as e:
        print("  [-] Unable to fetch %s/%s" % (url, filename))
        return None
    fp = open(save_path, "wb+")
    fp.write(request.read())
    fp.close()
    return save_path

def uncompress(path, dst):
    # Remove .tar.xz
    dirname = path[:-7]
    if os.path.isdir(dirname):
        return
    print("  [+] Uncompressing %s into %s/%s" % (path, dst, dirname))
    with tarfile.open(path) as f:
        f.extractall(dst)

def get_previous_data(year, month, day):
    # If day is undefined or if day is 1, we have to get the previous month
    # server descriptors data to get the descriptors.
    prev_sd_path = prev_ei_path = None
    if day == 0 or day == 1:
        prev_year = year
        prev_month = month
        if month == 1:
            prev_year -= 1
            prev_month = 12
        else:
            prev_month -= 1
        str_month = str(prev_month)
        if prev_month < 10:
            str_month = "0%d" % (prev_month)
        prev_sd_path = dl_server_descriptors(prev_year, str_month)
        prev_ei_path = dl_extra_infos(prev_year, str_month)
    return prev_sd_path, prev_ei_path

def create_csv_file(year, month, day):
    # Process the consensuses that we are interested in.
    csv_filename = 'data/relays-%s-%s-%s-00-00-00.csv' % \
            (year, month, day)
    if os.path.exists(csv_filename):
        print("  [+] CSV %s exists, skipping!" % (csv_filename))
        return None
    csv = open(csv_filename, 'w+')
    print("  [+] Creating CSV file %s" % (csv_filename))
    csv.write('Name,Fingerprint,Flags,IP,OrPort,ObservedBW,GuardClients,DirClients,Uptime,Longitude,Latitude)\n')
    return csv

def client_ips_to_string(ei_dict, sep):
    l = []
    for key, value in ei_dict.items():
        l.append('%s:%s' % (key, value))
    return sep.join(l)

def write_csv_data(consensus, sd_path, prev_sd_path, ei_path, prev_ei_path, year, month, day):
    """ Write data from consensus to CSV file """
    csv_fp = create_csv_file(year, month, day)
    if csv_fp is None:
        # CSV file already exists.
        return None

    for desc in consensus.routers.values():
        # Check for longitude and latitude. Without this, the entry is useless.
        lon, lat = geo_ip_lookup(desc.address)
        if lon is False and lat is False:
            continue

        fp = desc.fingerprint
        digest = desc.digest.lower()
        sd_filename = "%s/%s/%s/%s" % (sd_path[:-7], digest[0], digest[1], digest)
        try:
            sd = next(parse_file(sd_filename))
        except Exception as e:
            if prev_sd_path is None:
                continue
            sd_filename = "%s/%s/%s/%s" % (prev_sd_path[:-7], digest[0], digest[1], digest)
            try:
                sd = next(parse_file(sd_filename))
            except Exception as e:
                print("  [-] Server descriptor %s not found" % (digest))
                continue

        # Open extra info.
        entry_ips = ""
        dir_ips = ""
        if sd.extra_info_digest is not None:
            digest = sd.extra_info_digest.lower()
            ei_filename = "%s/%s/%s/%s" % (ei_path[:-7], digest[0], digest[1], digest)
            try:
                ei = next(parse_file(ei_filename))
            except Exception as e:
                if prev_ei_path is None:
                    continue
                ei_filename = "%s/%s/%s/%s" % (prev_ei_path[:-7], digest[0], digest[1], digest)
                try:
                    ei = next(parse_file(ei_filename))
                except Exception as e:
                    print("  [-] Extra info %s not found" % (ei_filename))
                    continue
            try:
                # Any Guard client ips?
                if ei.entry_ips is not None and len(ei.entry_ips) != 0:
                    entry_ips = client_ips_to_string(ei.entry_ips, "|")
            except Exception as e:
                pass
            try:
                # Any Directory client ips?
                if ei.dir_v3_requests is not None and len(ei.dir_v3_requests) != 0:
                    dir_ips = client_ips_to_string(ei.dir_v3_requests, "|")
            except Exception as e:
                pass

        # Get relay flags.
        flag = "M"
        if stem.Flag.GUARD in desc.flags:
            flag += "G"
        if stem.Flag.EXIT in desc.flags:
            flag += "E"
        if stem.Flag.HSDIR in desc.flags:
            flag += "H"

        csv_fp.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" % (desc.nickname,
            desc.fingerprint, flag, desc.address, desc.or_port,
            float(sd.observed_bandwidth/1000.0/1000.0), entry_ips,
            dir_ips, sd.uptime, lon, lat))
    csv_fp.close()

def make_monthly_csv(year, month, day):
    """
    Create the CSV files for the given year/month. If day is defined, only
    create the file for that day else all the day at midnight.
    """
    match_found = False
    str_month = str(month)
    if month < 10:
        str_month = "0%d" % (month)
    consensus_path = dl_consensus(year, str_month)
    if consensus_path is None:
        return None
    sd_path = dl_server_descriptors(year, str_month)
    ei_path = dl_extra_infos(year, str_month)
    if sd_path is None or ei_path is None:
        print("Unable to create CSV files for %s-%s" % (year, str_month))
        return None
    prev_sd_path, prev_ei_path = get_previous_data(year, month, day)
    if prev_sd_path is not None:
        uncompress(prev_sd_path, './server-descriptors')
        uncompress(prev_ei_path, './extra-infos')
    uncompress(consensus_path, './consensuses')
    uncompress(sd_path, './server-descriptors')
    uncompress(ei_path, './extra-infos')
    # We have the data, let's create the csv files for the requested date.
    for dir_day in os.listdir('./%s' % (consensus_path[:-7])):
        str_day = str(day)
        if day < 10:
            str_day = "0%d" % (day)
        if day != 0 and str_day != dir_day:
            continue
        match_found = True
        consensus_pathname = \
            "./consensuses/consensuses-%s-%s/%s/%s-%s-%s-00-00-00-consensus" % \
                (year, str_month, dir_day, year, str_month, dir_day)
        print("  [+] Reading consensus %s" % (consensus_pathname))
        try:
            consensus = next(parse_file(consensus_pathname, document_handler = DocumentHandler.DOCUMENT))
        except Exception as e:
            print("  [-] Consensus %s not found. Skipping!" % (consensus_pathname))
            continue

        # Nullify the previous path if we aren't the first of the month.
        if dir_day != "01":
            prev_ei_path = None
            prev_sd_path = None
        write_csv_data(consensus, sd_path, prev_sd_path, ei_path, prev_ei_path,
                str(year), str_month, dir_day)

    if match_found is False:
        print("  [-] Date not found in consensus")
    # Cleanup consensus and server descriptors for this month.
    #shutil.rmtree(consensus_path)
    #shutil.rmtree(sd_path)
    #if prev_sd_path is not None:
    #    shutil.rmtree(prev_sd_path)

def make_yearly_csv(year):
    """ DOC DOC """
    for month in range(1, 13):
        make_monthly_csv(year, month, 0)

def run(year, month, day):
    """
    Using the given date, download the needed files and create the csv file(s).
    """
    if month != 0:
        make_monthly_csv(year, month, day)
    else:
        make_yearly_csv(year)

    # Cleanup what's left if any.
    #for dirname in os.listdir('./consensuses'):
    #    shutil.rmtree(dirname)
    #for dirname in os.listdir('./server-descriptors'):
    #    shutil.rmtree(dirname)

def usage():
    print("Usage: %s <YEAR> [<MONTH> [<DAY>]]" % (sys.argv[0]))
    sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) == 1:
        usage()

    # Make sure we have a GeoIP database (maxmind)
    if not os.path.isfile(GEOIP_FILENAME):
        print("%s not found. It must be in the same directory as this script." % \
              GEOIP_FILENAME)
        print("Get the Maxmind city database here:")
        print("-> https://dev.maxmind.com/geoip/legacy/geolite")
        sys.exit(1)
    # Open GeoIP database.
    geoip_db = pygeoip.GeoIP(GEOIP_FILENAME)

    month = day = 0
    try:
        year = int(sys.argv[1])
        if len(sys.argv) > 2:
            month = int(sys.argv[2])
        if len(sys.argv) > 3:
            day = int(sys.argv[3])
    except ValueError as e:
        print("Invalid argument.")
        usage()

    # Create the data repository
    if not os.path.isdir("./data"):
        os.mkdir("./data")

    run(year, month, day)
