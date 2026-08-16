import os
import zipfile

def create_zip():
    zip_path = "public/zk-identity-fullstack.zip"
    os.makedirs("public", exist_ok=True)
    
    # Excluded directories and patterns
    exclude_dirs = {".git", ".next", "node_modules", "target", "dist", ".turbo", ".cache"}
    exclude_files = {"zk-identity-fullstack.zip", ".DS_Store"}
    
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk("."):
            # Modify dirs in-place to skip excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.startswith(".")]
            
            for file in files:
                if file in exclude_files or file.endswith(".tmp"):
                    continue
                
                # Relative path from project root
                rel_path = os.path.relpath(os.path.join(root, file), ".")
                # Normalize slashes
                arcname = rel_path.replace(os.sep, "/")
                
                if arcname.startswith("./"):
                    arcname = arcname[2:]
                
                # Skip if empty or root
                if not arcname:
                    continue
                    
                print(f"Adding: {arcname}")
                zf.write(rel_path, arcname)

    print(f"Zip created successfully at {zip_path}, size: {os.path.getsize(zip_path)} bytes")

if __name__ == "__main__":
    create_zip()
