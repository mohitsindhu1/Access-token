from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import time
import requests
import my_pb2
import output_pb2
import jwt

app = Flask(__name__)

# Global session to maintain cookies across requests
garena_session = requests.Session()
garena_session.headers.update({
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Connection": "keep-alive"
})

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

def encrypt_message(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def fetch_open_id(access_token):
    try:
        # Step 1: Inspect token to get UID
        uid_url = "https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/"
        uid_headers = {
            "authority": "prod-api.reward.ff.garena.com",
            "access-token": access_token,
            "origin": "https://reward.ff.garena.com",
            "referer": "https://reward.ff.garena.com/"
        }

        # Use the global session
        uid_res = garena_session.get(uid_url, headers=uid_headers, timeout=10)
        if uid_res.status_code != 200:
            return None, f"Garena inspect_token failed: {uid_res.status_code}"
            
        uid_data = uid_res.json()
        uid = uid_data.get("uid") or uid_data.get("data", {}).get("uid")
            
        if not uid:
            return None, f"Failed to extract UID from Garena: {uid_res.text}"

        # Step 2: Login with UID to get OpenID
        openid_url = "https://shop2game.com/api/auth/player_id_login"
        
        openid_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Requested-With": "com.garena.game.kgid",
            "User-Agent": "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)"
        }
        
        app_ids = [100067, 100065]
        last_error = "Unknown error"
        
        # Ensure session has initial cookies from shop2game if not already present
        if not garena_session.cookies.get_dict(domain="shop2game.com"):
            try:
                garena_session.get("https://shop2game.com/app", timeout=5)
            except:
                pass

        for app_id in app_ids:
            payload = {
                "app_id": app_id,
                "login_id": str(uid)
            }

            try:
                # Small delay to mimic human behavior
                time.sleep(1)
                
                # Copy current headers to avoid modifying global ones
                headers = openid_headers.copy()
                
                openid_res = garena_session.post(openid_url, headers=headers, json=payload, timeout=10)
                
                if openid_res.status_code == 200:
                    openid_data = openid_res.json()
                    if "open_id" in openid_data:
                        return openid_data["open_id"], None
                    elif "url" in openid_data and "captcha" in openid_data["url"]:
                        last_error = "Captcha detected"
                        # Try to refresh session on captcha
                        garena_session.cookies.clear()
                        garena_session.get("https://shop2game.com/app", timeout=5)
                        continue
                
                last_error = f"Status {openid_res.status_code}: {openid_res.text[:100]}"
            except Exception as e:
                last_error = str(e)

        return None, f"Could not bypass protection: {last_error}"

    except Exception as e:
        return None, f"Exception occurred: {str(e)}"

@app.route('/access-jwt', methods=['GET'])
def majorlogin_jwt():
    access_token = request.args.get('access_token')
    provided_open_id = request.args.get('open_id')

    if not access_token:
        return jsonify({"message": "missing access_token"}), 400

    open_id = provided_open_id
    if not open_id:
        open_id, error = fetch_open_id(access_token)
        if error:
            return jsonify({"message": error}), 400

    platforms = [8, 3, 4, 6]  

    for platform_type in platforms:
        game_data = my_pb2.GameData()
        game_data.timestamp = "2024-12-05 18:15:32"
        game_data.game_name = "free fire"
        game_data.game_version = 1
        game_data.version_code = "1.108.3"
        game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
        game_data.device_type = "Handheld"
        game_data.network_provider = "Verizon Wireless"
        game_data.connection_type = "WIFI"
        game_data.screen_width = 1280
        game_data.screen_height = 960
        game_data.dpi = "240"
        game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
        game_data.total_ram = 5951
        game_data.gpu_name = "Adreno (TM) 640"
        game_data.gpu_version = "OpenGL ES 3.0"
        game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
        game_data.ip_address = "172.190.111.97"
        game_data.language = "en"
        game_data.open_id = open_id
        game_data.access_token = access_token
        game_data.platform_type = platform_type
        game_data.field_99 = str(platform_type)
        game_data.field_100 = str(platform_type)

        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(serialized_data)
        hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB51"
        }
        edata = bytes.fromhex(hex_encrypted_data)

        try:
            response = requests.post(url, data=edata, headers=headers, verify=False, timeout=5)

            if response.status_code == 200:
                data_dict = None
                try:
                    example_msg = output_pb2.Garena_420()
                    example_msg.ParseFromString(response.content)
                    data_dict = {field.name: getattr(example_msg, field.name)
                                 for field in example_msg.DESCRIPTOR.fields
                                 if field.name not in ["binary", "binary_data", "Garena420"]}
                except Exception:
                    try:
                        data_dict = response.json()
                    except ValueError:
                        continue  

                if data_dict and "token" in data_dict:
                    token_value = data_dict["token"]
                    try:
                        decoded_token = jwt.decode(token_value, options={"verify_signature": False})
                    except Exception as e:
                        decoded_token = {}

                    result = {
                        "account_id": decoded_token.get("account_id"),
                        "account_name": decoded_token.get("nickname"),
                        "open_id": open_id,
                        "access_token": access_token,
                        "platform": decoded_token.get("external_type"),
                        "region": decoded_token.get("lock_region"),
                        "status": "success",
                        "token": token_value
                    }
                    return jsonify(result), 200
        except requests.RequestException:
            continue  

    return jsonify({"message": "No valid platform found"}), 400

@app.route('/token', methods=['GET'])
def oauth_guest():
    uid = request.args.get('uid')
    password = request.args.get('password')
    if not uid or not password:
        return jsonify({"message": "Missing uid or password"}), 400

    oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }

    try:
        oauth_response = requests.post(oauth_url, data=payload, headers=headers, timeout=5)
    except requests.RequestException as e:
        return jsonify({"message": str(e)}), 500

    if oauth_response.status_code != 200:
        try:
            return jsonify(oauth_response.json()), oauth_response.status_code
        except ValueError:
            return jsonify({"message": oauth_response.text}), oauth_response.status_code

    try:
        oauth_data = oauth_response.json()
    except ValueError:
        return jsonify({"message": "Invalid JSON response from OAuth service"}), 500

    if 'access_token' not in oauth_data or 'open_id' not in oauth_data:
        return jsonify({"message": "OAuth response missing access_token or open_id"}), 500

    params = {
        'access_token': oauth_data['access_token'],
        'open_id': oauth_data['open_id']
    }
    
    with app.test_request_context('/api/token', query_string=params):
        return majorlogin_jwt()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)