pipeline {
  agent any

  environment {
    GIT_CREDENTIALS_ID = 'github-token'
    DEFECTDOJO_URL = 'https://defectdojo.dev4cloud.online'
    DEFECTDOJO_TOKEN = 'b496d5dd233e7de0fb3f27721d9a76160cfdf7a4'
 
  }

  stages {

    stage('OWASP Dependency Check') {
      steps {
        sh '''
          mkdir -p reports
          curl -L -o dc.zip https://github.com/jeremylong/DependencyCheck/releases/download/v8.4.0/dependency-check-8.4.0-release.zip
          unzip -o dc.zip -d dc
          chmod +x dc/dependency-check/bin/dependency-check.sh
          ./dc/dependency-check/bin/dependency-check.sh \
            --project amazon-poc \
            --scan . \
            --format XML \
            --out reports \
            --disableAssembly
        '''
      }
    }

    stage('Trivy Dependencies') {
      steps {
        sh '''
          mkdir -p reports
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -
          ./bin/trivy fs . \
            --scanners vuln \
            --vuln-type library \
            --format json \
            --output reports/trivy-deps.json
        '''
      }
    }
    stage('Criar Engagement DefectDojo') {
      steps {
        script {
          def today = sh(script: "date +%F", returnStdout: true).trim()
          def response = sh(
            script: """
              curl -s -X POST https://defectdojo.dev4cloud.online/api/v2/engagements/ \\
                -H "Authorization: Token b496d5dd233e7de0fb3f27721d9a76160cfdf7a4" \\
                -H "Content-Type: application/json" \\
                -d '{
                      "name": "Build-${env.BUILD_NUMBER}",
                      "product": 2,
                      "engagement_type": "CI/CD",
                      "target_start": "${today}",
                      "target_end": "${today}",
                      "status": "In Progress",
                      "active": true
                    }'
            """,
            returnStdout: true
          ).trim()
        
          def engagementId = new groovy.json.JsonSlurperClassic().parseText(response).id
          env.ENGAGEMENT_ID = "${engagementId}" 
        }

      }
    }
    stage('Publicar Relatórios') {
      steps {
        archiveArtifacts artifacts: 'reports/*.json'

        // Enviar OWASP
        sh '''
          curl -X POST "$DEFECTDOJO_URL/api/v2/import-scan/" \
            -H "Authorization: Token $DEFECTDOJO_TOKEN" \
            -F "engagement=$ENGAGEMENT_ID" \
            -F "scan_type=Dependency Check Scan" \
            -F "minimum_severity=Low" \
            -F "active=true" \
            -F "verified=true" \
            -F "file=@reports/dependency-check-report.xml" \
            -F "scan_date=$(date +%F)" \
            -F "tags=sca,owasp" \
            -F "close_old_findings=false" \
            -F "description=Relatório gerado pelo OWASP Dependency-Check (POC SCA)"
        '''

        // Enviar Trivy
        sh '''
          curl -X POST "$DEFECTDOJO_URL/api/v2/import-scan/" \
            -H "Authorization: Token $DEFECTDOJO_TOKEN" \
            -F "engagement=$ENGAGEMENT_ID" \
            -F "scan_type=Trivy Scan" \
            -F "minimum_severity=Low" \
            -F "active=true" \
            -F "verified=true" \
            -F "file=@reports/trivy-deps.json" \
            -F "scan_date=$(date +%F)" \
            -F "tags=sca,trivy" \
            -F "close_old_findings=false" \
            -F "description=Relatório gerado pelo Trivy (POC SCA)"
        '''
      }
    }
  }
}
