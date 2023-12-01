from django.shortcuts import render, get_object_or_404,redirect
from rest_framework.views import APIView
from .serializers import *
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework import status
from rest_framework.response import Response
from django.core.exceptions import ObjectDoesNotExist
from django.urls import reverse

from .models import Userinfo
import jwt

from django.contrib.auth import authenticate, get_user_model
from base.settings import SECRET_KEY
from rest_framework_simplejwt.tokens import RefreshToken
# from django.contrib.auth.hashers import check_password
import socket

from rest_framework.decorators import api_view
from .forms import LoginForm

#form 사용법
# @api_view(['POST', 'GET'])
def test(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            user = Userinfo()
            user.subsr = form.cleaned_data['subsr']
            user.is_active = 1
            user.save()
            return redirect('admin/')
    else:
        form = LoginForm()
        context = {'form': form}
        return render(request, 'test.html', context)
    # else:
        # return Response({"message":"method err"}, status= status.HTTP_400_BAD_REQUEST)

#login 성공시 
@api_view(('GET',))
def login_suc(request):
    if request.method == 'GET':
        access = request.COOKIES['access']
        payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
        pk = payload.get('userinfo_subsr')
        user = get_object_or_404(Userinfo, pk = pk)
        serializer = UserSerializer(instance = user)
        user_id = serializer.data.get('subsr', None)
        return Response({"user":user_id}, status= status.HTTP_200_OK)

def process_request(request):  
        override_method = request.META.get('X-HTTP-Method-Override')
        if request.method=='GET' and not override_method: 
            # Override method in case of PUT requests and header not already set
            request.META['X-HTTP-Method-Override'] = 'POST' # set to desired method value
        return request


#login 상태 확인
@api_view(('GET',))
def status_check(request):
    # if request.method == 'POST':
        # return redirect('login')
    if request.method == 'GET':
        try:
            access = request.COOKIES['access']
            # return redirect(test)
            # return Response(serializer.data, status= status.HTTP_200_OK)
        except KeyError:
            # request._method = 'POST'
            request = process_request(request)
            return redirect('logins')
            # return Response({"message": "key error"}, status = status.HTTP_403_FORBIDDEN)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)
            # return redirect(request.POST.get('login_success') or 'login_success')
        else:
            try:
                payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
                pk = payload.get('userinfo_subsr')
                user = get_object_or_404(Userinfo, pk = pk)
                serializer = UserSerializer(instance = user)
                user_id = serializer.data.get('subsr', None)
                if user_id != None:
                    return redirect(request.GET.get('next') or 'login_success')
                # return redirect(login_suc, user.pk)
                else:
                    return redirect('login')
            except jwt.InvalidSignatureError:
                return redirect('login')
                return Response({"message":"inv"}, status= status.HTTP_400_BAD_REQUEST)
            except(jwt.exceptions.ExpiredSignatureError):
            #token 만료 시 갱신
                data = {'refresh': request.COOKIES.get('refresh', None)}
                serializer = TokenObtainPairSerializer(data = data)
                if serializer.is_valid(raise_exception=True):
                    access = serializer.data.get('access', None)
                    refresh = serializer.data.get('refresh', None)
                    payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
                    pk = payload.get('userinfo_subsr')
                    user = get_object_or_404(Userinfo, pk = pk)
                    serializer = UserSerializer(instance = user)
                    res = Response(serializer.data, status=status.HTTP_200_OK)
                    res.set_cookie('access', access)
                    res.set_cookie('refresh', refresh)
                    return res
                return jwt.exceptions.InvalidTokenError
            except(jwt.exceptions.InvalidTokenError):
                #사용 불가 토큰인 경우
                return redirect(request.POST.get('next') or 'login')
            # return Response(status=status.HTTP_400_BAD_REQUEST)
            except (jwt.exceptions.InvalidKeyError):
                return redirect(request.POST.get('next') or 'login')


@api_view(('POST',)) # postman으로 back test할 때 response가 json 형식으로 되어 있어서 사용 -> html 이동시 삭제 가능
def login(request):
    if request.method == 'POST':
        # ch, sid = status_check(request._request)
        # if ch == 0:
        #     return Response(sid, status= status.HTTP_200_OK)
        # else:

        try:
            subsr = request.data['subsr'] # input 가져오기
            # id = request.POST.get('id')
            user = Userinfo.objects.filter(subsr = subsr).first() #db에서 데이터 가져오기

            if user is None: #예외처리1 - 일치하는 데이터가 없는 경우
                 return Response(
                    {'message': "회원 가입 후 이용해 주세요."},
                    status = status.HTTP_400_BAD_REQUEST
                )

            serializer = UserSerializer(user)
            token = TokenObtainPairSerializer.get_token(user) #refresh token 생성
            refresh_token = str(token) #token 문자열화
            access_token = str(token.access_token)
            #활성화 toggle
            user.is_active = True
            user.save()
            #ip 정보 get
            x_fowarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_fowarded_for:
                ip = x_fowarded_for.split(',')[0]
            else:
                ip = request.META.get('REMOTE_ADDR')
            
          
        except KeyError: # json 형식이 잘못 넘어온 경우
            return Response(
                {"message":"아이디를 입력해 주세요"},
                status= status.HTTP_204_NO_CONTENT
            )

        except Exception as e: #예외 처리
             if "'NoneType'" in str(e) or 'expected a number' in str(e): #숫자 형식 이외의 입력이 있는 경우
                 return Response(
                     {"message":"아이디는 숫자 형태 입니다."},
                     status= status.HTTP_406_NOT_ACCEPTABLE
                 )
             if "Expecting value" in str(e): #id 입력이 없는 경우
                 return Response(
                     {"message": "아이디는 필수 입니다."},
                     status = status.HTTP_400_BAD_REQUEST
                 )
             else: #이외 예외 상황
                return Response(
                    {'message':'아이디 확인 후 다시 입력해 주세요.',
                     "error": str(e)},
                    status= status.HTTP_400_BAD_REQUEST
                )
        else: # 예외 없는 경우 - 쿠키에 토큰 저장
            #back test 용
            res = Response(
                {
                    "user": serializer.data,
                    "ip": ip,
                    "message": "로그인 성공",
                    "token": {
                        "access": access_token,
                        "refresh": refresh_token,
                    },
                },
                status = status.HTTP_200_OK,
            )

            #front 연결
            # res = HttpResponse(render(request, 'login.html', {'id': id}))
            res.set_cookie("access", access_token, httponly=True)
            res.set_cookie("refresh", refresh_token, httponly= True)

            return res
            

class SignupAPIView(APIView):
    def post(self, request):

        # x_fowarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

        # if x_fowarded_for:
        #     ip = x_fowarded_for.split(',')[0]
        # else:
        #     ip = request.META.get('REMOTE_ADDR')
            

        ip = socket.gethostbyname(socket.gethostname())

        request.data['ip'] = ip
        serializer = SingupSerializer(data = request.data)
        if serializer.is_valid():
            user = serializer.save()
            #jwt token 접근
            token = TokenObtainPairSerializer.get_token(user)
            refresh_token = str(token)
            access_token = str(token.access_token)
            res = Response(
                {
                    "user": serializer.data,
                    "ip": ip,
                    "message":"register success",
                    "token":{
                        "access": access_token, 
                        "refresh": refresh_token,
                    },
                },
                status= status.HTTP_200_OK,
            )
            #cookie에 넣어주기
            res.set_cookie("access", access_token, httponly= True)
            res.set_cookie("refresh", refresh_token, httponly= True)
            return res
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    #user 정보 확인
    def get(self, request):
        try:
            #access token decode -> id 추출 = user 식별
            access = request.COOKIES['access']
            payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
            pk = payload.get('user_id')
            user = get_object_or_404(Userinfo, pk = pk)
            serializer = UserSerializer(instance = user)
            return Response(serializer.data, status= status.HTTP_200_OK)
        except(jwt.exceptions.ExpiredSignatureError):
            #token 만료 시 갱신
            data = {'refresh': request.COOKIES.get('refresh', None)}
            serializer = TokenObtainPairSerializer(data = data)
            if serializer.is_valid(raise_exception=True):
                access = serializer.data.get('access', None)
                refresh = serializer.data.get('refresh', None)
                payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
                pk = payload.get('user_id')
                serializer = UserSerializer(instance = user)
                res = Response(serializer.data, status=status.HTTP_200_OK)
                res.set_cookie('access', access)
                res.set_cookie('refresh', refresh)
                return res
            return jwt.exceptions.InvalidTokenError
        except(jwt.exceptions.InvalidTokenError):
            #사용 불가 토큰인 경우
            return Response(status=status.HTTP_400_BAD_REQUEST)
        
    #로그인
    def post(self, request):
        id = request.data['id']
        user = Userinfo.objects.filter(id = id).first()

        # x_fowarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

        # if x_fowarded_for:
        #     ip = x_fowarded_for.split(',')[0]
        # else:
        #     ip = request.META.get('REMOTE_ADDR')

        ip = socket.gethostbyname(socket.gethostname())


        #user 존재 X
        if user is None:
            return Response(
                {'message': "id Not exists."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # if user.ip != ip:
        #     return Response(
        #         {"message": "if you changed ur set top box please make a call to CS service center"}, 
        #         status=status.HTTP_303_SEE_OTHER
        #     )

        if user is not None:
            serializer = UserSerializer(user)
            token = TokenObtainPairSerializer.get_token(user) #refresh token 생성
            refresh_token = str(token) #token 문자열화
            access_token = str(token.access_token)

            user.is_active = True
            user.save()

            x_fowarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

            if x_fowarded_for:
                ip = x_fowarded_for.split(',')[0]
            else:
                ip = request.META.get('REMOTE_ADDR')


            res = Response(
                {
                    "user": serializer.data,
                    "ip": ip,
                    "message": "login success",
                    "token": {
                        "access": access_token,
                        "refresh": refresh_token,
                    },
                },
                status = status.HTTP_200_OK,
            )

            res.set_cookie("access", access_token, httponly=True)
            res.set_cookie("refresh", refresh_token, httponly= True)
            return res
        else:
            return Response(
                {"message": "login failed"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
    def delete(self, request):
        update_user = Userinfo.objects.get(id = request.data['id'])
        update_user.is_active = False
        update_user.save()

        #cookie에 저장된 token 삭제 -> logout 처리
        res = Response({
            "message": "Log out success"
        }, status= status.HTTP_202_ACCEPTED)
        res.delete_cookie('refresh')
        return res
    
