# Generated by Django 4.1.7 on 2023-05-14 11:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0003_remove_doctor_image_doctor_image_url'),
    ]

    operations = [
        migrations.AlterField(
            model_name='doctor',
            name='image_url',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
