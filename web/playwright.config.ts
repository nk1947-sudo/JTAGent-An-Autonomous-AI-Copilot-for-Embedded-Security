import { defineConfig } from '@playwright/test';
export default defineConfig({
 testDir:'.', testMatch:'demo.spec.ts', use:{baseURL:'http://127.0.0.1:8000',headless:true,viewport:{width:1500,height:1000}},
 webServer:{command:'uv run --project .. python ../scripts/demo.py --skip-build',
  url:'http://127.0.0.1:8000/healthz',reuseExistingServer:false,timeout:30000,
  env:{DASHBOARD_PASSWORD:'browser-test-password',TARGET_BACKEND:'mock',INFERENCE_BACKEND:'scripted'}},
});
