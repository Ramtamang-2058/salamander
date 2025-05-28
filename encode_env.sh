#!/bin/bash
# encode_env.sh - Script to properly encode your .env file for GitHub secrets

echo "🔐 Encoding .env file for GitHub secrets..."

if [ ! -f ".env" ]; then
    echo "❌ .env file not found!"
    exit 1
fi

# Create base64 encoded version
echo "📝 Creating base64 encoded .env..."
base64 -w 0 .env > .env.b64

echo "✅ Base64 encoded .env created as .env.b64"
echo ""
echo "📋 Copy this value for UNGABLE_MIXED42_B64 GitHub secret:"
echo "----------------------------------------"
cat .env.b64
echo ""
echo "----------------------------------------"
echo ""
echo "🔥 For FIREBASE_CONFIG secret, copy the entire JSON content from:"
echo "config/salamanders-122ec-firebase-adminsdk-fbsvc-8c226bb171.json"
echo ""
echo "⚠️  Make sure to copy the raw JSON without any extra formatting!"

# Clean up
rm .env.b64