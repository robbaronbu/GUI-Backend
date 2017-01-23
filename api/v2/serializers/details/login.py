from core.models import Login
from rest_framework import serializers

from api.v2.serializers.summaries import UserSummarySerializer
from api.v2.serializers.fields.base import UUIDHyperlinkedIdentityField


class LoginSerializer(serializers.HyperlinkedModelSerializer):
    #created_by = UserSummarySerializer(read_only=True)
    url = UUIDHyperlinkedIdentityField(
        view_name='api:v2:login-detail',
        uuid_field='id'
    )

    class Meta:
        model = Login 
        fields = (
            'id',
            'url',
            'Username',
            'UnscopedToken',
            'ScopedToken',
            # Adtl. Fields
            #'created_by'
        )
