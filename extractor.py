import tarfile


def extract_metadata(apk_path):
    package_info = {}
    try:
        with tarfile.open(apk_path, 'r:gz') as tar:
            found_pkginfo = False
            for member in tar.getmembers():
                if member.name.endswith('.PKGINFO'):
                    found_pkginfo = True
                    f = tar.extractfile(member)
                    data = f.read().decode(errors='ignore')

                    for line in data.splitlines():
                        if line.startswith("pkgname"):
                            package_info["name"] = line.split("=")[1].strip()
                        elif line.startswith("pkgver"):
                            package_info["version"] = line.split("=")[1].strip()

            if not found_pkginfo:
                raise ValueError("No valid .PKGINFO file found in the .apk package")

            if "name" not in package_info or "version" not in package_info:
                raise ValueError("Failed to extract package name or version")

    except Exception as e:
        print(f"Error extracting metadata: {e}")
        exit(1)

    return package_info