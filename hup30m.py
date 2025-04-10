import streamlit as st
import hashlib
from collections import deque, Counter

st.set_page_config(page_title="Tool Dự Đoán Tài Xỉu", layout="wide")
st.markdown("""
    <style>
    .main-title {
        font-size: 2.5em;
        text-align: center;
        font-weight: bold;
        margin-bottom: 1em;
    }
    .card {
        background-color: #f9f9f9;
        padding: 1.5em;
        border-radius: 20px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        margin-bottom: 2em;
    }
    .highlight {
        font-size: 1.3em;
        font-weight: bold;
        color: #0072C6;
    }
    </style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-title">🎲 Dự Đoán Tài Xỉu & Phân Tích Cầu SUNWIN</div>', unsafe_allow_html=True)

if 'db' not in st.session_state:
    st.session_state.db = {
        'users': {
            'admin': {'password': 'admin123', 'role': 'admin', 'active_key': None},
            'giangson2102': {'password': 'son2102', 'role': 'admin', 'active_key': None},
        },
        'used_keys': set(["2102"]),
        'recent_results': deque(maxlen=10),
        'logged_in': False,
        'username': None,
        'role': None,
        'pending_users': set()
    }

db = st.session_state.db

# === Core functions ===
def complex_calculation(input_str: str) -> float:
    md5_hash = int(hashlib.md5(input_str.encode()).hexdigest(), 16)
    sha256_hash = int(hashlib.sha256(input_str.encode()).hexdigest(), 16)
    blake2b_hash = int(hashlib.blake2b(input_str.encode()).hexdigest(), 16)
    combined_hash = (md5_hash % 100) * 0.3 + (sha256_hash % 100) * 0.4 + (blake2b_hash % 100) * 0.3
    return combined_hash % 100

def bayesian_adjustment(recent_results: deque) -> float:
    count = Counter(recent_results)
    total = len(recent_results)
    if total == 0:
        return 50.0
    prob_xiu = (count["Xỉu"] + 1) / (total + 2)
    return prob_xiu * 100

def detect_trend(recent_results: deque) -> str:
    if len(recent_results) < 4:
        return "Không đủ dữ liệu phân tích cầu."
    trend_str = ''.join(['T' if res == "Tài" else 'X' for res in recent_results])
    patterns = {
        "TTTT": "Cầu bệt Tài",
        "XXXX": "Cầu bệt Xỉu",
        "TXTX": "Cầu 1-1",
        "TXT": "Cầu 1-2-1",
        "TTTX": "Cầu bệt ngắt (Tài ngắt)",
        "XXXT": "Cầu bệt ngắt (Xỉu ngắt)",
        "TXXT": "Cầu 2-1-2",
        "XXTXX": "Cầu 3-2",
    }
    for pattern, label in patterns.items():
        if trend_str.endswith(pattern):
            return label
    if "TTT" in trend_str[-5:] and trend_str[-1] == "X":
        return "Cầu bẻ từ Tài sang Xỉu"
    elif "XXX" in trend_str[-5:] and trend_str[-1] == "T":
        return "Cầu bẻ từ Xỉu sang Tài"
    return "Cầu không xác định"

def adjust_prediction(percentage: float, trend: str) -> float:
    adjustments = {
        "Cầu bệt Tài": -7,
        "Cầu bệt Xỉu": +7,
        "Cầu 1-1": 5 if percentage > 50 else -5,
        "Cầu 1-2-1": 3,
        "Cầu bệt ngắt (Tài ngắt)": 2,
        "Cầu bệt ngắt (Xỉu ngắt)": 2,
        "Cầu 2-1-2": -4,
        "Cầu 3-2": 6,
        "Cầu bẻ từ Tài sang Xỉu": 10,
        "Cầu bẻ từ Xỉu sang Tài": -10,
    }
    return max(0, min(100, percentage + adjustments.get(trend, 0)))

# === Menu ===
menu = st.sidebar.selectbox("🔐 Chọn chức năng:", ["Phân tích", "Đăng nhập", "Đăng ký", "👑 Quản lý Key (Admin)"])

if menu == "Phân tích":
    if db['logged_in']:
        with st.container():
            st.markdown('<div class="card">', unsafe_allow_html=True)
            input_str = st.text_input("🎰 Nhập mã phiên hoặc chuỗi bất kỳ:")
            analysis_mode = st.radio("🧠 Chế độ phân tích:", ["Cơ bản", "Nâng cao (AI + Phân tích cầu)"])
            if input_str:
                base_percent = complex_calculation(input_str)
                trend = detect_trend(db['recent_results'])
                bayes_percent = bayesian_adjustment(db['recent_results'])
                final_percent = base_percent if analysis_mode == "Cơ bản" else adjust_prediction(bayes_percent, trend)

                st.subheader("📊 Kết quả dự đoán")
                st.markdown(f"**🟢 Tài:** <span class='highlight'>{100 - final_percent:.2f}%</span>", unsafe_allow_html=True)
                st.markdown(f"**🔵 Xỉu:** <span class='highlight'>{final_percent:.2f}%</span>", unsafe_allow_html=True)
            else:
                trend = detect_trend(db['recent_results'])

            st.markdown(f"**📈 Phân tích cầu:** `{trend}`")
            st.markdown("🕓 Lịch sử gần đây:")
            st.write(list(db['recent_results']))

            result = st.selectbox("📝 Nhập kết quả thực tế:", ["", "Tài", "Xỉu"])
            if result:
                db['recent_results'].append(result)
                st.success(f"✅ Đã lưu kết quả: {result}")
            st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning("🔒 Bạn cần đăng nhập để sử dụng công cụ phân tích")

elif menu == "Đăng ký":
    with st.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("📝 Đăng ký tài khoản")
        new_username = st.text_input("Tên tài khoản mới")
        new_password = st.text_input("Mật khẩu", type="password")
        if st.button("Tạo tài khoản"):
            if new_username in db['users']:
                st.error("❌ Tài khoản đã tồn tại.")
            else:
                db['users'][new_username] = {"password": new_password, "role": "user", "active_key": None}
                st.success("✅ Đăng ký thành công.")
                st.info("📌 Vui lòng đăng nhập và chờ admin cấp key.")
        st.markdown('</div>', unsafe_allow_html=True)

elif menu == "Đăng nhập":
    with st.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("🔐 Đăng nhập")
        username = st.text_input("Tên tài khoản")
        password = st.text_input("Mật khẩu", type="password")
        user_key = st.text_input("🔑 Nhập key kích hoạt")
        if st.button("Đăng nhập"):
            user_data = db['users'].get(username)
            if user_data and user_data["password"] == password:
                if user_data["role"] == "admin":
                    db['logged_in'] = True
                    db['username'] = username
                    db['role'] = "admin"
                    st.success("✅ Đăng nhập admin thành công")
                elif not user_data.get("active_key"):
                    db['pending_users'].add(username)
                    st.warning("🚧 Tài khoản chưa được cấp key. Vui lòng chờ admin.")
                elif user_key == user_data.get("active_key") and user_key not in db['used_keys']:
                    db['logged_in'] = True
                    db['username'] = username
                    db['role'] = "user"
                    db['used_keys'].add(user_key)
                    db['users'][username]["active_key"] = None
                    st.success(f"🎉 Đăng nhập thành công. Chào {username}!")
                else:
                    st.error("❌ Sai key hoặc key đã được sử dụng.")
            else:
                st.error("❌ Sai tài khoản hoặc mật khẩu.")
        st.markdown('</div>', unsafe_allow_html=True)

elif menu == "👑 Quản lý Key (Admin)":
    if db.get("role") == "admin":
        with st.container():
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.subheader("🔑 Cấp Key Kích Hoạt Cho Tài Khoản")

            if db['pending_users']:
                st.markdown("### 👥 Danh sách chờ cấp key")
                for user in list(db['pending_users']):
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.markdown(f"**🔹 {user}**")
                    with col2:
                        key_input = st.text_input(f"Key cho {user}", key=f"key_{user}")
                        if st.button(f"Cấp key cho {user}", key=f"btn_{user}"):
                            if key_input in db['used_keys']:
                                st.error("❌ Key đã được dùng.")
                            else:
                                db['users'][user]['active_key'] = key_input
                                db['pending_users'].remove(user)
                                st.success(f"✅ Đã cấp key cho {user}")
            else:
                st.info("📭 Không có tài khoản nào đang chờ cấp key.")
            st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.warning("🔒 Chỉ tài khoản admin mới truy cập được mục này.")
