# PhishNet

PhishNet is a sophisticated AI security platform designed to combat phishing and social engineering in real time. It provides a multi layered defense system that analyzes both text based communications and audio streams to identify potential threats.

## Overview

PhishNet addresses the growing threat of AI generated phishing attacks. By combining natural language processing with advanced audio spectral analysis, the platform helps users verify the authenticity of emails and voice conversations.

## Key Features

* Email Phishing Detection: Uses a fine tuned BERT model to identify malicious intent in email text.
* Real Time Audio Analysis: Detects deepfake audio streams using spectral features and deep learning models.
* Sentiment and Tone Analysis: Evaluates messages for psychological triggers like urgency and financial pressure.
* Visual Risk Assessment: Provides clear risk levels and confidence scores through an interactive dashboard.
* Flag System: Highlights specific indicators of risk such as abnormal zero crossing rates or suspicious vocabulary.

## Technology Stack

* Frontend: Built with React, Vite, and Tailwind CSS for a responsive and performant user interface.
* Backend: Powered by FastAPI to handle high concurrency requests and WebSocket connections.
* Machine Learning: Utilizes PyTorch and HuggingFace Transformers for NLP tasks.
* Audio Processing: Employs Librosa and NumPy for extraction of spectral features from raw audio data.

## Project Structure

* backend: Contains the FastAPI application, machine learning model logic, and feature extraction pipelines.
* frontend: Contains the React source code, components for risk visualization, and audio capture logic.
* models: Directory for storing local model weights and scalers used in analysis.

## Installation

### Backend Setup

1. Navigate to the backend directory.
2. Create a virtual environment: python -m venv venv
3. Activate the virtual environment.
4. Install dependencies: pip install -r requirements.txt

### Frontend Setup

1. Navigate to the frontend directory.
2. Install dependencies: npm install

## Usage

1. Start the backend server: python -m uvicorn main:app --reload
2. Start the frontend development server: npm run dev
3. Access the application in your browser at the provided local URL.

## Technical Details

The audio detection pipeline fuses spectral features such as MFCC variance, spectral flatness, and zero crossing rate with a high performance transformer model from HuggingFace. This hybrid approach ensures robust detection against various types of synthetic speech vocoders.

The email analysis component performs simultaneous phishing classification and sentiment analysis to provide a holistic view of the risk profile of incoming messages.
