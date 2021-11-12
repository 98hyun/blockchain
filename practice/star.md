### library

hashlib 

hashlib 암호화 혹은 잘게나누는 lib.   
sha256방식은 256bit 크기여서.  

방법은 문자열-> 인코딩(.encode()) -> sha256안에 넣고. -> 16진수로 변경.(hexdigest())

uuid4

universal unique id 거의 겹칠일 없다. 

bcrypt

암호화 라이브러리.  
단방향으로만 암호화해서. 거꾸로 복호화하는것이 거의 어렵다.   
그래서 회원이 친 password와 같은지만 확인.  

jwt

json web token.  
https://fenderist.tistory.com/142  

flask_jwt_extended 랑 같이 쓰여서 token 조작이 가능.  

urllib 

https://velog.io/@city7310/%ED%8C%8C%EC%9D%B4%EC%8D%AC%EC%9C%BC%EB%A1%9C-URL-%EA%B0%80%EC%A7%80%EA%B3%A0-%EB%86%80%EA%B8%B0


### concept 

blockchain 

chain과 current_transactions 들이 있고, 겹치지 않는 nodes들이있다. 

new_block은 block에 정보를 담는다.   
hash 클래스 안에서도 접근 할 수 있게. staticmethod로 
hashlib.sha256로 암호화.  


### trick
 
틀만 짜기.    

### backend

redirect(path)   
from flask import session 후 dict 형태로 접근.  


