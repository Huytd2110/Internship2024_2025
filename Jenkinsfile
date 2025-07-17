pipeline {
    agent any
    stages {
        stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/Huytd2110/Internship2024_2025.git'
            }
        }
        stage('Set up Python') {
            steps {
                sh 'python3 -m venv venv'
                sh '. venv/bin/activate && pip install -r requirements.txt'
            }
        }
        stage('Run Pentest') {
            steps {
                sh '. venv/bin/activate && python3 main.py'
            }
        }
        stage('Archive Report Artifacts') {
            steps {
                archiveArtifacts artifacts: 'output/**', fingerprint: true
            }
        }
    }
}
