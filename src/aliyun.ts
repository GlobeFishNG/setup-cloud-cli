import * as core from '@actions/core';
import * as exec from '@actions/exec';

export interface AliyunParameters {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
}

export async function runAliyun(params: AliyunParameters): Promise<void> {
  // eslint-disable-next-line i18n-text/no-en
  core.info(`Setup aliyun for region ${params.region}`);
  const aliyunCli = 'aliyun';
  const args = [
    'configure',
    '--profile',
    'default',
    '--mode',
    'AK',
    '--region',
    params.region,
    '--access-key-id',
    params.accessKeyId,
    '--access-key-secret',
    params.secretAccessKey
  ];

  const statusCode = await exec.exec(aliyunCli, args);

  if (statusCode !== 0) {
    throw new Error(`Failed to run aliyun cli with exitCode ${statusCode}`);
  }
}
