# utils.py

from datetime import datetime, timedelta
from typing import Optional
from fastapi import HTTPException, status
from jose import jwt, JWTError


# JWT 토큰을 위한 비밀 키 및 알고리즘
SECRET_KEY = 'asdf-wert-cvbd-eeegy'
ALGORITHM = 'HS256'


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    JWT Access Token을 생성합니다.
    - 데이터와 만료 시간을 포함하여 토큰을 인코딩합니다.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        # 만료 시간이 지정되지 않은 경우 1시간으로 설정
        expire = datetime.now() + timedelta(hours=1)
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> dict:
    """
    JWT Access Token을 검증하고 페이로드를 반환합니다.
    - 토큰이 유효하지 않거나 만료된 경우 예외를 발생시킵니다.
    """
    try:
        # 토큰 디코딩
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get('sub')
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='유효하지 않은 토큰입니다.')
        return payload
    except JWTError:
        # JWT 디코딩 오류 발생 시
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='유효하지 않은 토큰입니다.')