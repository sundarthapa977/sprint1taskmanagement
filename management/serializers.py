from django.contrib.auth.models import User
from .models import Team, Project, Task, Subtask, Comment, Attachment, Notification
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

class TeamSerializer(serializers.ModelSerializer):
    class Meta:
        model = Team
        fields = ('team_id', 'name', 'description')
        read_only_fields = 'lead_user_id'

class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = ('project_id', 'name', 'description', 'start_date', 'end_date', 'status')
        read_only_field = ('username', 'team_id')

class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ('task_id', 'title','description', 'due_date', 'status', 'priority')
        read_only_fields = ('username', 'project_id')

class SubtaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subtask
        fields = ('subtask_id', 'name', 'description', 'due_date', 'status')

class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = ('comment_id', 'text', 'timestamp')
        read_only_fields = ('task_id', 'username')

class AttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attachment
        fields = ('attachment_id', 'file_path', 'upload_date')
        read_only_fields = 'task_id'

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ('notification_id', 'message', 'read_status', 'timestamp')
        read_only_fields = 'username'

class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'}, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, style={'input_type': 'password'}, required=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'password2', 'email', 'first_name', 'last_name')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'password': {'write_only': True, 'min_length': 6},
            'password2': {'write_only': True, 'min_length': 6}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )
        user.set_password(validated_data['password'])
        user.save()

        return user

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('pk', 'username', 'is_superuser', 'first_name', 'last_name', 'email')
