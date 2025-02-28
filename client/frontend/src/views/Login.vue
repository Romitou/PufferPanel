<script setup>
import { ref, inject } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import Btn from '@/components/ui/Btn.vue'
import defaultRoute from '@/router/defaultRoute'

const { t } = useI18n()
const api = inject('api')
const events = inject('events')
const validate = inject('validate')
const router = useRouter()

function loggedIn() {
  try {
    router.push(JSON.parse(sessionStorage.getItem('returnTo')))
    sessionStorage.removeItem('returnTo')
  } catch {
    router.push(defaultRoute(api))
  }
  events.emit('login')
}

async function login() {
  const res = await api.auth.loginCloudflare()
  if (res === true) {
    loggedIn()
  }
}

login();
</script>

<template>
  <div class="login">
    <h1 v-text="t('users.Login')" />
    Merci de patienter pendant l'authentification automatique de votre session en validant votre identité avec Cloudflare Access.
    <btn color="primary" @click="login()" v-text="t('users.Login')" />
  </div>
</template>
