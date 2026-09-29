set(src
  in_gcs.c
  in_gcs_auth.c
  )

FLB_PLUGIN(in_gcs "${src}" "")
