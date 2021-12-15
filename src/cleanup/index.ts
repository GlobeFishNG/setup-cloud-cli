import * as core from '@actions/core';
import * as io from '@actions/io';

async function cleanup(): Promise<void> {
  try {
    // The GitHub Actions toolkit does not have an option to completely unset
    // environment variables, so we overwrite the current value with an empty
    // string. The AWS CLI and AWS SDKs will behave correctly: they treat an
    // empty string value as if the environment variable does not exist.
    core.exportVariable('AWS_ACCESS_KEY_ID', '');
    core.exportVariable('AWS_SECRET_ACCESS_KEY', '');
    core.exportVariable('AWS_SESSION_TOKEN', '');
    core.exportVariable('AWS_DEFAULT_REGION', '');
    core.exportVariable('AWS_REGION', '');
    io.rmRF('~/.aliyun');
  } catch (error) {
    core.setFailed((error as Error).message);
  }
}

cleanup();
