import argparse
import os

parser = argparse.ArgumentParser(description="Delete test pods.")

parser.add_argument(
    "-n",
    "--name",
    dest="pod_name",
)


parser.add_argument("-a", "--all", action="store_true")

args = parser.parse_args()

os.system("solid stop")

if args.all:
    os.system("sudo rm -rf /opt/solid/server/")

else:
    os.system(f"sudo rm -rf /opt/solid/server/{args.pod_name}")
    
    # WARNING Be very careful with this. This searches for a pod_name in various files.
    # But if I am removing pod named `abc` and there is another pod `abcdef` then both 
    # would seem to get wiped out.
    #
    # ALSO the use of * is very problematic!!!!!!!
    
    os.system(
        f"grep -nrl '{args.pod_name}*' /opt/solid/server/.internal/ | sudo"
        " xargs rm -r"
    )

os.system("solid start")
