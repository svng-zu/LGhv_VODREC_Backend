from django.db import models

class UserManager():
    def create_user(self, subsr, ip,  **kwargs):
        if not id:
            raise ValueError("ID is required")

        user = self.model(
            subsr = subsr,
            ip = ip,
            **kwargs
        )

        user.save(using = self._db)
        return user
    
    def create_superuser(self, subsr, ip,  **kwargs):
        superuser = self.create_user(
            subsr = subsr,
            ip = ip
        )
        superuser.is_staff = True
        superuser.is_superuser = True
        superuser.is_active = True

        superuser.save(using = self._db)
        return superuser
    

# class User(models.Model):
#     id = models.IntegerField(primary_key= True)
    
#     # ip = models.CharField(max_length = 25, unique=True)
#     ip = models.CharField(max_length = 25, blank= True, null = True)

#     is_superuser = models.BooleanField(default = False)
#     is_staff = models.BooleanField(default=False)
#     is_active = models.BooleanField(default = False)
#     joined_date =models.DateTimeField(auto_now_add=True)
#     objects = UserManager()
#     USERNAME_FIELD = 'id'
#     # db_table = 'user'
#     class Meta:
#         db_table="user"


class Userinfo(models.Model):
    subsr = models.IntegerField(default= None)
    subsr_id = models.IntegerField(primary_key=True) #FK -> USERinfo
    kids = models.BooleanField(default=0) #0이 kids 기록 없는거
    ip = models.CharField(max_length = 25, blank= True, null = True)

    is_superuser = models.BooleanField(default = False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default = False)

    objects = UserManager()
    USERNAME_FIELD = 'subsr'
    
    class Meta:
        db_table="userinfo"

class VOD_INFO(models.Model):
    program_name = models.CharField(max_length=255, default=None)
    ct_cl = models.CharField(max_length=50)
    poster_id = models.IntegerField(primary_key=True, default=0)
    poster_url = models.URLField(max_length=1000, default=None)
    release_date = models.IntegerField(null=True, blank=True)
    program_genre = models.CharField(max_length=255, default=None)
    age_limit = models.CharField(max_length=20, default=15)
    nokids = models.IntegerField()
    program_id = models.CharField(max_length=100)
    e_bool = models.BooleanField(default=0) #0인게 모델 사용(event x)
    summary = models.CharField(null =True, max_length=2000)
    actor = models.CharField(null = True, max_length=100)

    def __str__(self):
        return self.program_name
    class Meta:
        db_table="vodinfo"


class EVOD_INFO(models.Model):
    program_name = models.CharField(max_length=255, default=None)
    ct_cl = models.CharField(max_length=50)
    poster_id = models.IntegerField(primary_key=True, default=0)
    poster_url = models.URLField(max_length=1000, default=None)
    release_date = models.IntegerField(null=True, blank=True)
    program_genre = models.CharField(max_length=255, default=None)
    age_limit = models.CharField(max_length=20, default=15)
    nokids = models.IntegerField(default=0)
    program_id = models.CharField(max_length=20, default = 000)
    summary = models.CharField(null = True, max_length=2000)
    actor = models.CharField(null = True, max_length=100)


    def __str__(self):
        return self.program_name
    class Meta:
        db_table="evodinfo"


class CONlog(models.Model):
    subsr = models.IntegerField()
    SMRY = models.TextField(max_length= 2000)
    ACTR_DISP = models.CharField(max_length=10)
    disp_rtm = models.CharField(max_length=10)
    pinfo = models.CharField(max_length=10)
    disp_rtm_sec = models.IntegerField()
    poster_id = models.IntegerField()
    episode_num = models.IntegerField(null= True)
    log_dt = models.DateTimeField()
    year = models.IntegerField()
    month = models.IntegerField()
    day = models.IntegerField()
    hour = models.IntegerField()
    minute = models.IntegerField()
    second = models.IntegerField()
    weekday = models.IntegerField()
    day_name = models.CharField(max_length=20)
    subsr_id = models.IntegerField(primary_key=True) #FK -> USERinfo
    kids = models.IntegerField()
    program_name = models.CharField(max_length=255)
    ct_cl = models.CharField(max_length=50)
    release_date = models.IntegerField(null=True, blank=True)
    program_genre = models.CharField(max_length=255)
    age_limit = models.CharField(max_length=20)
    nokids = models.IntegerField(default=0)
    program_id = models.IntegerField()
    e_bool = models.IntegerField(default=0) #0인게 모델 사용(event x)

    class Meta :
        db_table = 'contlog'

class VODLog(models.Model):
    subsr = models.IntegerField()
    use_tms = models.IntegerField()
    SMRY = models.TextField(max_length=2000)
    ACTR_DISP = models.CharField(max_length=10)
    disp_rtm = models.CharField(max_length=10)
    upload_date = models.DateTimeField()
    pinfo = models.CharField(max_length=10)
    disp_rtm_sec = models.IntegerField()
    poster_id = models.IntegerField()
    episode_num = models.IntegerField()
    log_dt = models.DateTimeField()
    year = models.IntegerField()
    month = models.IntegerField()
    day = models.IntegerField()
    hour = models.IntegerField()
    minute = models.IntegerField()
    second = models.IntegerField()
    weekday = models.IntegerField()
    day_name = models.CharField(max_length=20)
    subsr_id = models.IntegerField(primary_key=True) #FK -> USERinfo
    kids = models.IntegerField()
    program_name = models.CharField(max_length=255)
    ct_cl = models.CharField(max_length=50)
    release_date = models.IntegerField(null=True, blank=True)
    program_genre = models.CharField(max_length=255)
    age_limit = models.CharField(max_length=20)
    nokids = models.IntegerField()
    program_id = models.IntegerField()
    count_watch = models.IntegerField()
    e_bool = models.IntegerField(default=0) #0인게 모델 사용(event x)

    class Meta:
        db_table = 'vodlog'