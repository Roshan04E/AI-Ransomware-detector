import hashlib
import aiofiles
import aiohttp
import asyncio

class VTIsMalicious:
    # Your VirusTotal API Key
    API_KEY = "b55521d99967e7b1c7234130ec227616e6b16d59bdbdced12389fb5fbddb13be"
    # VirusTotal API endpoint for file hash report
    URL = "https://www.virustotal.com/api/v3/files/"

    def __init__(self, file):
        self.file = file
    
    async def file_to_hash(self, filepath: str, algorithm: str = "sha256") -> str:
        """
        Compute the hash of a file using the specified algorithm asynchronously.

        :param filepath: Path to the file to hash.
        :param algorithm: Hashing algorithm to use (default is 'sha256').
                          Options: 'md5', 'sha1', 'sha256'.
        :return: The computed hash as a string.
        """
        try:
            # Validate the hashing algorithm
            if algorithm not in hashlib.algorithms_available:
                raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from: {', '.join(hashlib.algorithms_available)}")
            
            # Initialize the hasher
            hasher = hashlib.new(algorithm)
            
            # Read the file in chunks to avoid memory issues with large files asynchronously
            async with aiofiles.open(filepath, "rb") as f:
                while chunk := await f.read(4096):
                    hasher.update(chunk)
            
            # Return the hex digest of the hash
            return hasher.hexdigest()
        except FileNotFoundError:
            return {"Error": f"File not found at {filepath}"}
        except Exception as e:
            return {"Error": f"{e}"}

    async def check_file_hash(self) -> dict:
        # Compute the hash of the file
        file_hash = await self.file_to_hash(self.file)
        
        if "Error" in file_hash:
            return {"Error": file_hash}  # Return Error message in a dictionary format
        
        headers = {"x-apikey": self.API_KEY}
        try:
            # Asynchronously fetch the file hash report from VirusTotal API
            async with aiohttp.ClientSession() as session:
                async with session.get(self.URL + file_hash, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        if "data" in data:
                            attributes = data["data"]["attributes"]
                            malicious_count = attributes.get("last_analysis_stats", {}).get("malicious", 0)
                            total_engines = sum(attributes.get("last_analysis_stats", {}).values())
                            
                            result = {
                                "hash": file_hash,
                                "Malicious Detections": f"{malicious_count}/{total_engines}",
                                "inference": "Malicious" if malicious_count > 0 else "Clean"
                            }
                            return result
                        else:
                            return {"Error": f"No data found for hash: {file_hash}"}
                    else:
                        if response.status == 404:
                            return {"Error": "File Hash not in the Database!"}
                        else:
                            return {"Error": f"Error: {response.status} - {response.text}"}
        except Exception as e:
            return {"Error": f"An Error occurred: {e}"}

async def check_file(file_path: str):
    # Create an instance of VTIsMalicious with the file path
    vt_checker = VTIsMalicious(file_path)
    
    # Call check_file_hash to get the result
    result = await vt_checker.check_file_hash()
    print(result)
    return result


async def get_hash(file_path: str):
    vt_checker = VTIsMalicious(file_path)
    file_hash = await vt_checker.file_to_hash(file_path)
    return file_hash


# if __name__ == '__main__':
# # # Example usage:
#     file_path = "/home/rosn/Documents/PROJECTS/RANSOWARE/RBACK_v1/datasets/ransomwares/Babuk/113c3c3aeafbc59615cc23cd47b0cb1f22145ed6d7bfeca283c3fdf4d8076881.elf"
#     # # Run asynchronously
#     result = asyncio.run(get_hash(file_path))
