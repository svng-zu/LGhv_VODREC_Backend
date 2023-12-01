# Generated by Django 4.2.3 on 2023-11-30 06:34

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Userinfo',
            fields=[
                ('subsr', models.IntegerField(default=None)),
                ('subsr_id', models.IntegerField(default=0, primary_key=True, serialize=False)),
                ('kids', models.BooleanField(default=0)),
                ('is_superuser', models.BooleanField(default=False)),
                ('is_staff', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=False)),
            ],
            options={
                'db_table': 'userinfo',
            },
        ),
        migrations.CreateModel(
            name='VOD_INFO',
            fields=[
                ('program_id', models.IntegerField(default=None, primary_key=True, serialize=False)),
                ('program_name', models.CharField(default='', max_length=255)),
                ('ct_cl', models.CharField(max_length=50)),
                ('image_id', models.IntegerField(default=None)),
                ('poster_url', models.URLField(default=None, max_length=1000)),
                ('release_date', models.IntegerField(blank=True, null=True)),
                ('program_genre', models.CharField(default=None, max_length=255)),
                ('age_limit', models.CharField(default=15, max_length=20)),
                ('Nokids', models.IntegerField(default=0)),
                ('e_bool', models.BooleanField(default=0)),
                ('SMRY', models.CharField(max_length=2000, null=True)),
                ('ACTR_DISP', models.CharField(max_length=100, null=True)),
            ],
            options={
                'db_table': 'vodinfo',
            },
        ),
        migrations.CreateModel(
            name='VODLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('program_id', models.IntegerField(default=0)),
                ('subsr', models.IntegerField(null=True)),
                ('use_tms', models.IntegerField(null=True)),
                ('SMRY', models.TextField(max_length=2000)),
                ('ACTR_DISP', models.CharField(max_length=10)),
                ('disp_rtm', models.CharField(max_length=10)),
                ('upload_date', models.DateTimeField(null=True)),
                ('pinfo', models.CharField(max_length=10)),
                ('disp_rtm_sec', models.IntegerField(null=True)),
                ('image_id', models.IntegerField(null=True)),
                ('episode_num', models.IntegerField(null=True)),
                ('log_dt', models.DateTimeField(null=True)),
                ('year', models.IntegerField(null=True)),
                ('month', models.IntegerField(null=True)),
                ('day', models.IntegerField(null=True)),
                ('hour', models.IntegerField(null=True)),
                ('minute', models.IntegerField(null=True)),
                ('second', models.IntegerField(null=True)),
                ('weekday', models.IntegerField(null=True)),
                ('day_name', models.CharField(max_length=20)),
                ('kids', models.IntegerField(null=True)),
                ('program_name', models.CharField(max_length=255)),
                ('ct_cl', models.CharField(max_length=50)),
                ('release_date', models.IntegerField(blank=True, null=True)),
                ('program_genre', models.CharField(max_length=255)),
                ('age_limit', models.CharField(max_length=20)),
                ('nokids', models.IntegerField(null=True)),
                ('count_watch', models.IntegerField(null=True)),
                ('e_bool', models.IntegerField(default=0)),
                ('poster_url', models.URLField(default='', max_length=2000, null=True)),
                ('subsr_id', models.ForeignKey(default=0, on_delete=django.db.models.deletion.CASCADE, related_name='user_infos', to='service.userinfo')),
            ],
            options={
                'db_table': 'vodlog',
            },
        ),
        migrations.CreateModel(
            name='CONlog',
            fields=[
                ('program_id', models.IntegerField(default=0, primary_key=True, serialize=False)),
                ('subsr', models.IntegerField()),
                ('SMRY', models.TextField(max_length=2000)),
                ('ACTR_DISP', models.CharField(max_length=10)),
                ('disp_rtm', models.CharField(max_length=10)),
                ('pinfo', models.CharField(max_length=10)),
                ('disp_rtm_sec', models.IntegerField(null=True)),
                ('image_id', models.IntegerField(null=True)),
                ('episode_num', models.IntegerField(null=True)),
                ('log_dt', models.DateTimeField(null=True)),
                ('year', models.IntegerField(null=True)),
                ('month', models.IntegerField(null=True)),
                ('day', models.IntegerField(null=True)),
                ('hour', models.IntegerField(null=True)),
                ('minute', models.IntegerField(null=True)),
                ('second', models.IntegerField(null=True)),
                ('weekday', models.IntegerField(null=True)),
                ('day_name', models.CharField(max_length=20)),
                ('kids', models.IntegerField(null=True)),
                ('program_name', models.CharField(max_length=255)),
                ('ct_cl', models.CharField(max_length=50)),
                ('release_date', models.IntegerField(blank=True, null=True)),
                ('program_genre', models.CharField(max_length=255)),
                ('age_limit', models.CharField(max_length=20)),
                ('nokids', models.IntegerField(default=0)),
                ('e_bool', models.IntegerField(default=0)),
                ('poster_url', models.URLField(max_length=2000, null=True)),
                ('subsr_id', models.ForeignKey(default=0, on_delete=django.db.models.deletion.CASCADE, related_name='con_logs', to='service.vodlog')),
            ],
            options={
                'db_table': 'contlog',
            },
        ),
    ]