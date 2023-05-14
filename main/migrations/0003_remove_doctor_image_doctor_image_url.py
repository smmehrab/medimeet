# Generated by Django 4.1.7 on 2023-05-14 10:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0002_remove_doctor_image_url_doctor_image'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='doctor',
            name='image',
        ),
        migrations.AddField(
            model_name='doctor',
            name='image_url',
            field=models.CharField(blank=True, max_length=255),
        ),
    ]
