# users.py

from passlib.context import CryptContext

# 비밀번호 해시를 위한 CryptContext 객체 생성
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """
    비밀번호를 해시하여 반환합니다.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    평문 비밀번호와 해시된 비밀번호를 비교합니다.
    """
    return pwd_context.verify(plain_password, hashed_password)


# --- 인메모리 데이터베이스 역할 ---

# 사용자 정보를 저장하는 리스트 (딕셔너리 형태)
# 예: [{user_id: User 객체}]
users = []

# 사용자별 대화 기록을 저장하는 딕셔너리
# 예: {user_id: [{"role": "user", "message": "안녕"}, ...]}
conversation_history = {}

# 탈퇴한 사용자 정보를 임시로 저장하는 리스트
removed_users = []