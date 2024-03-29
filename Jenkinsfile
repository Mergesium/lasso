@Library('eo-jenkins-lib@main') import eo.Utils

pipeline {
    agent any
    stages {
        stage('Unit Tests') {
            steps {
                sh './jenkins.sh'
            }
        }
        stage('Packaging') {
            when {
                expression {
                   currentBuild.result == null || currentBuild.result == 'SUCCESS'
                }
                anyOf {
                   tag 'v*'
                   branch 'main'
                }
            }
            steps {
                script {
                    env.SHORT_JOB_NAME=sh(
                        returnStdout: true,
                        // given JOB_NAME=gitea/project/PR-46, returns project
                        // given JOB_NAME=project/main, returns project
                        script: '''
                            echo "${JOB_NAME}" | sed "s/gitea\\///" | awk -F/ '{print $1}'
                        '''
                    ).trim()
                    if (env.GIT_BRANCH == 'main' || env.GIT_BRANCH == 'origin/main') {
                        sh "sudo -H -u eobuilder /usr/local/bin/eobuilder -d bullseye,bookworm ${SHORT_JOB_NAME}"
                    } else if (env.GIT_BRANCH.startsWith('hotfix/')) {
                        sh "sudo -H -u eobuilder /usr/local/bin/eobuilder -d bullseye,bookworm --branch ${env.GIT_BRANCH} --hotfix ${SHORT_JOB_NAME}"
                    }
                }
            }
        }
    }
    post {
        success {
            cleanWs()
        }
    }
}
