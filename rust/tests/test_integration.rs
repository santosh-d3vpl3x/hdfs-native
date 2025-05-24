#[cfg(feature = "integration-test")]
mod common;

#[cfg(feature = "integration-test")]
mod test {
    use crate::common::{assert_bufs_equal, TEST_FILE_INTS};
    use bytes::{BufMut, BytesMut};
    use futures::{StreamExt, stream::TryStreamExt};
    use hdfs_native::{
        acl::AclEntry,
        client::FileStatus,
        minidfs::{DfsFeatures, MiniDfs},
        Client, Result, WriteOptions,
    };
    use serial_test::serial;
    use std::collections::HashSet;

    #[tokio::test]
    #[serial]
    async fn test_basic_non_ha() {
        test_with_features(&HashSet::new()).await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_security_kerberos() {
        test_with_features(&HashSet::from([DfsFeatures::Security]))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_security_token() {
        test_with_features(&HashSet::from([DfsFeatures::Security, DfsFeatures::Token]))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_integrity_kerberos() {
        test_with_features(&HashSet::from([
            DfsFeatures::Security,
            DfsFeatures::Integrity,
        ]))
        .await
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_integrity_token() {
        test_with_features(&HashSet::from([
            DfsFeatures::Security,
            DfsFeatures::Token,
            DfsFeatures::Integrity,
        ]))
        .await
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_privacy_kerberos() {
        test_with_features(&HashSet::from([
            DfsFeatures::Security,
            DfsFeatures::Privacy,
        ]))
        .await
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_privacy_token() {
        test_with_features(&HashSet::from([
            DfsFeatures::Security,
            DfsFeatures::Token,
            DfsFeatures::Privacy,
        ]))
        .await
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_aes() {
        test_with_features(&HashSet::from([
            DfsFeatures::Security,
            DfsFeatures::Privacy,
            DfsFeatures::AES,
        ]))
        .await
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_forced_data_transfer_encryption() {
        // DataTransferEncryption enabled but privacy isn't, still force encryption
        test_with_features(&HashSet::from([
            DfsFeatures::Security,
            DfsFeatures::DataTransferEncryption,
        ]))
        .await
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_data_transfer_encryption() {
        test_with_features(&HashSet::from([
            DfsFeatures::Security,
            DfsFeatures::Privacy,
            DfsFeatures::DataTransferEncryption,
        ]))
        .await
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_data_transfer_encryption_aes() {
        test_with_features(&HashSet::from([
            DfsFeatures::Security,
            DfsFeatures::Privacy,
            DfsFeatures::DataTransferEncryption,
            DfsFeatures::AES,
        ]))
        .await
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_basic_ha() {
        test_with_features(&HashSet::from([DfsFeatures::HA]))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_security_privacy_ha() {
        test_with_features(&HashSet::from([
            DfsFeatures::Security,
            DfsFeatures::Privacy,
            DfsFeatures::HA,
        ]))
        .await
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_security_token_ha() {
        test_with_features(&HashSet::from([
            DfsFeatures::Security,
            DfsFeatures::Token,
            DfsFeatures::HA,
        ]))
        .await
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_rbf() {
        test_with_features(&HashSet::from([DfsFeatures::RBF]))
            .await
            .unwrap();
    }

    pub async fn test_with_features(features: &HashSet<DfsFeatures>) -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let _dfs = MiniDfs::with_features(features);
        let client = Client::default();

        let mut file = client.create("/testfile", WriteOptions::default()).await?;
        for i in 0..TEST_FILE_INTS as i32 {
            file.write(i.to_be_bytes().to_vec().into()).await?;
        }
        file.close().await?;

        test_file_info(&client).await?;
        test_listing(&client).await?;
        test_rename(&client).await?;
        test_dirs(&client).await?;
        test_read_write(&client).await?;
        // We use writing to create files, so do this after
        test_recursive_listing(&client).await?;
        test_set_times(&client).await?;
        test_set_owner(&client).await?;
        test_set_permission(&client).await?;
        test_set_replication(&client).await?;
        test_get_content_summary(&client).await?;
        test_acls(&client).await?;
        test_glob_features(&client).await?;

        Ok(())
    }

    async fn test_glob_features(client: &Client) -> Result<()> {
        test_list_status_glob(client).await?;
        test_delete_glob(client).await?;
        test_get_content_summary_glob(client).await?;
        Ok(())
    }

    async fn test_list_status_glob(client: &Client) -> Result<()> {
        client.mkdirs("/test_glob", 0o755, true).await?;
        client
            .create("/test_glob/file1.txt", WriteOptions::default())
            .await?
            .close()
            .await?;
        client
            .create("/test_glob/file2.log", WriteOptions::default())
            .await?
            .close()
            .await?;
        client.mkdirs("/test_glob/subdir", 0o755, true).await?;
        client
            .create("/test_glob/subdir/file3.txt", WriteOptions::default())
            .await?
            .close()
            .await?;
        client.mkdirs("/test_glob/otherdir", 0o755, true).await?;
        client
            .create("/test_glob/otherdir/file4.dat", WriteOptions::default())
            .await?
            .close()
            .await?;

        // 1. Test basic glob
        let stream_basic = client.list_status_glob("/test_glob/*.txt")?;
        let statuses: Vec<FileStatus> = stream_basic.try_collect().await?;
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].path, "/test_glob/file1.txt");

        // Test recursive glob using existing list_status logic (glob doesn't handle **)
        // The original list_status_glob was changed to just call get_file_info,
        // so this test case's intent might need re-evaluation if it relied on old list_status_glob behavior.
        // Assuming the glob pattern itself handles the depth.
        let stream_recursive = client.list_status_glob("/test_glob/*/*.txt")?;
        let statuses_recursive: Vec<FileStatus> = stream_recursive.try_collect().await?;
        assert_eq!(statuses_recursive.len(), 1);
        assert_eq!(statuses_recursive[0].path, "/test_glob/subdir/file3.txt");

        // Verify FileStatus details (example for one file)
        let file1_status = client.get_file_info("/test_glob/file1.txt").await?;
        assert_eq!(statuses[0].length, file1_status.length);
        assert_eq!(statuses[0].isdir, file1_status.isdir);

        // 2. Test glob with no matches
        let stream_no_match = client.list_status_glob("/test_glob/*.csv")?;
        let statuses_no_match: Vec<FileStatus> = stream_no_match.try_collect().await?;
        assert!(statuses_no_match.is_empty());

        // 3. Test glob matching a directory
        let stream_dir = client.list_status_glob("/test_glob/subdir")?;
        let statuses_dir: Vec<FileStatus> = stream_dir.try_collect().await?;
        assert_eq!(statuses_dir.len(), 1);
        assert_eq!(statuses_dir[0].path, "/test_glob/subdir");
        assert!(statuses_dir[0].isdir);

        // 4. Test glob matching everything in a directory
        let stream_all = client.list_status_glob("/test_glob/*")?;
        let statuses_all_results: Vec<FileStatus> = stream_all.try_collect().await?;
        let mut paths: Vec<String> = statuses_all_results.into_iter().map(|s| s.path).collect();
        paths.sort(); // Sort for consistent order
        assert_eq!(paths.len(), 4);
        assert_eq!(
            paths,
            vec![
                "/test_glob/file1.txt",
                "/test_glob/file2.log",
                "/test_glob/otherdir",
                "/test_glob/subdir"
            ]
        );

        client.delete("/test_glob", true).await?;
        Ok(())
    }

    async fn test_delete_glob(client: &Client) -> Result<()> {
        client.mkdirs("/test_glob_delete", 0o755, true).await?;
        client
            .create("/test_glob_delete/deleteme1.txt", WriteOptions::default())
            .await?
            .close()
            .await?;
        client
            .create("/test_glob_delete/deleteme2.txt", WriteOptions::default())
            .await?
            .close()
            .await?;
        client
            .create("/test_glob_delete/keepme.txt", WriteOptions::default())
            .await?
            .close()
            .await?;

        // 1. Test deleting multiple files
        client
            .delete_glob("/test_glob_delete/deleteme*.txt", false)
            .await?;
        assert!(client
            .get_file_info("/test_glob_delete/deleteme1.txt")
            .await
            .is_err());
        assert!(client
            .get_file_info("/test_glob_delete/deleteme2.txt")
            .await
            .is_err());
        assert!(client
            .get_file_info("/test_glob_delete/keepme.txt")
            .await
            .is_ok());

        // 2. Test deleting with no matches
        client
            .delete_glob("/test_glob_delete/nonexistent*.txt", false)
            .await?;
        // No error should occur, keepme.txt should still be there
        assert!(client
            .get_file_info("/test_glob_delete/keepme.txt")
            .await
            .is_ok());

        client.delete("/test_glob_delete", true).await?;

        // 3. Test deleting recursively
        client
            .mkdirs("/test_glob_delete_rec/dir1", 0o755, true)
            .await?;
        client
            .create(
                "/test_glob_delete_rec/dir1/file1.txt",
                WriteOptions::default(),
            )
            .await?
            .close()
            .await?;
        client
            .mkdirs("/test_glob_delete_rec/dir2", 0o755, true)
            .await?;
        client
            .create(
                "/test_glob_delete_rec/dir2/file2.txt",
                WriteOptions::default(),
            )
            .await?
            .close()
            .await?;

        client.delete_glob("/test_glob_delete_rec/*", true).await?;
        assert!(client
            .get_file_info("/test_glob_delete_rec/dir1")
            .await
            .is_err());
        assert!(client
            .get_file_info("/test_glob_delete_rec/dir2")
            .await
            .is_err());
        assert!(
            client
                .list_status("/test_glob_delete_rec", false)
                .await
                .is_err()
                || client
                    .list_status("/test_glob_delete_rec", false)
                    .await?
                    .is_empty()
        );

        client.delete("/test_glob_delete_rec", true).await.ok(); // path may not exist
        Ok(())
    }

    async fn test_get_content_summary_glob(client: &Client) -> Result<()> {
        client.mkdirs("/test_glob_summary", 0o755, true).await?;
        let mut file_a = client
            .create("/test_glob_summary/fileA.txt", WriteOptions::default())
            .await?;
        file_a.write(vec![0u8; 10].into()).await?;
        file_a.close().await?;

        let mut file_b = client
            .create("/test_glob_summary/fileB.log", WriteOptions::default())
            .await?;
        file_b.write(vec![0u8; 20].into()).await?;
        file_b.close().await?;

        client
            .create(
                "/test_glob_summary/ignored_file.dat",
                WriteOptions::default(),
            )
            .await?
            .close()
            .await?;

        // 1. Test with multiple files
        let summary = client
            .get_content_summary_glob("/test_glob_summary/file*")
            .await?;
        assert_eq!(summary.length, 30);
        assert_eq!(summary.file_count, 2);
        assert_eq!(summary.directory_count, 0);

        // 2. Test with no matches
        let summary_no_match = client
            .get_content_summary_glob("/test_glob_summary/nothing*")
            .await?;
        assert_eq!(summary_no_match.length, 0);
        assert_eq!(summary_no_match.file_count, 0);
        assert_eq!(summary_no_match.directory_count, 0);

        client.delete("/test_glob_summary", true).await?;

        // 3. Test with a mix of files and directories
        client.mkdirs("/test_glob_summary_mix", 0o755, true).await?;
        let mut data_txt = client
            .create("/test_glob_summary_mix/data.txt", WriteOptions::default())
            .await?;
        data_txt.write(vec![0u8; 5].into()).await?;
        data_txt.close().await?;

        client
            .mkdirs("/test_glob_summary_mix/folder", 0o755, true)
            .await?;
        let mut another_txt = client
            .create(
                "/test_glob_summary_mix/folder/another.txt",
                WriteOptions::default(),
            )
            .await?;
        another_txt.write(vec![0u8; 15].into()).await?;
        another_txt.close().await?;

        // The glob crate's default behavior for "*" does not descend into directories.
        // So, it will match data.txt and folder.
        let summary_mix = client
            .get_content_summary_glob("/test_glob_summary_mix/*")
            .await?;
        assert_eq!(summary_mix.length, 5); // Only data.txt
        assert_eq!(summary_mix.file_count, 1); // Only data.txt
        assert_eq!(summary_mix.directory_count, 1); // folder

        // To include contents of subdirectories, a pattern like /test_glob_summary_mix/*/* would be needed
        // or by iterating and calling get_content_summary recursively.
        // For this test, we'll make another call to sum things up as the current implementation would.
        let summary_mix_folder_contents = client
            .get_content_summary_glob("/test_glob_summary_mix/folder/*")
            .await?;

        assert_eq!(summary_mix_folder_contents.length, 15);
        assert_eq!(summary_mix_folder_contents.file_count, 1);
        assert_eq!(summary_mix_folder_contents.directory_count, 0);

        client.delete("/test_glob_summary_mix", true).await?;
        Ok(())
    }

    async fn test_file_info(client: &Client) -> Result<()> {
        let status = client.get_file_info("/testfile").await?;
        // Path is empty, I guess because we already know what file we just got the info for?
        assert_eq!(status.path, "/testfile");
        assert_eq!(status.length, TEST_FILE_INTS * 4);
        Ok(())
    }

    async fn test_listing(client: &Client) -> Result<()> {
        let statuses: Vec<FileStatus> = client
            .list_status("/", false)
            .await?
            .into_iter()
            // Only include files, since federation things could result in folders being created
            .filter(|s| !s.isdir)
            .collect();
        assert_eq!(statuses.len(), 1);
        let status = &statuses[0];
        assert_eq!(status.path, "/testfile");
        assert_eq!(status.length, TEST_FILE_INTS * 4);
        Ok(())
    }

    async fn test_rename(client: &Client) -> Result<()> {
        client.rename("/testfile", "/testfile2", false).await?;

        assert!(client.list_status("/testfile", false).await.is_err());
        assert_eq!(client.list_status("/testfile2", false).await?.len(), 1);

        client.rename("/testfile2", "/testfile", false).await?;
        assert!(client.list_status("/testfile2", false).await.is_err());
        assert_eq!(client.list_status("/testfile", false).await?.len(), 1);

        Ok(())
    }

    async fn test_dirs(client: &Client) -> Result<()> {
        client.mkdirs("/testdir", 0o755, false).await?;
        assert!(client
            .list_status("/testdir", false)
            .await
            .is_ok_and(|s| s.is_empty()));

        client.delete("/testdir", false).await?;
        assert!(client.list_status("/testdir", false).await.is_err());

        client.mkdirs("/testdir1/testdir2", 0o755, true).await?;
        assert!(client
            .list_status("/testdir1", false)
            .await
            .is_ok_and(|s| s.len() == 1));

        // Deleting non-empty dir without recursive fails
        assert!(client.delete("/testdir1", false).await.is_err());
        assert!(client.delete("/testdir1", true).await.is_ok_and(|r| r));

        Ok(())
    }

    async fn test_read_write(client: &Client) -> Result<()> {
        let write_options = WriteOptions::default().overwrite(true);

        // Create an empty file
        let mut writer = client.create("/newfile", &write_options).await?;

        writer.close().await?;

        assert_eq!(client.get_file_info("/newfile").await?.length, 0);

        let mut writer = client.create("/newfile", &write_options).await?;

        let mut file_contents = BytesMut::new();
        let mut data = BytesMut::new();
        for i in 0..1024 {
            file_contents.put_i32(i);
            data.put_i32(i);
        }

        let buf = data.freeze();

        writer.write(buf).await?;
        writer.close().await?;

        assert_eq!(client.get_file_info("/newfile").await?.length, 4096);

        let mut reader = client.read("/newfile").await?;
        let read_data = reader.read(reader.file_length()).await?;

        assert_bufs_equal(&file_contents, &read_data, None);

        let mut data = BytesMut::new();
        for i in 0..1024 {
            file_contents.put_i32(i);
            data.put_i32(i);
        }

        let buf = data.freeze();

        let mut writer = client.append("/newfile").await?;
        writer.write(buf).await?;
        writer.close().await?;

        let mut reader = client.read("/newfile").await?;
        let read_data = reader.read(reader.file_length()).await?;

        assert_bufs_equal(&file_contents, &read_data, None);

        assert!(client.delete("/newfile", false).await.is_ok_and(|r| r));

        client.mkdirs("/testdir", 0o755, true).await?;
        assert!(client.read("/testdir").await.is_err());
        client.delete("/testdir", true).await?;

        Ok(())
    }

    async fn test_recursive_listing(client: &Client) -> Result<()> {
        let write_options = WriteOptions::default();
        client.mkdirs("/dir/nested", 0o755, true).await?;
        client
            .create("/dir/file1", &write_options)
            .await?
            .close()
            .await?;
        client
            .create("/dir/nested/file2", &write_options)
            .await?
            .close()
            .await?;
        client
            .create("/dir/nested/file3", &write_options)
            .await?
            .close()
            .await?;

        let statuses = client.list_status("/dir", true).await?;
        assert_eq!(statuses.len(), 4);

        client.delete("/dir", true).await?;

        Ok(())
    }

    async fn test_set_times(client: &Client) -> Result<()> {
        client
            .create("/test", WriteOptions::default())
            .await?
            .close()
            .await?;

        let mtime = 1717641455;
        let atime = 1717641456;

        client.set_times("/test", mtime, atime).await?;

        let file_info = client.get_file_info("/test").await?;

        assert_eq!(file_info.modification_time, mtime);
        assert_eq!(file_info.access_time, atime);

        client.delete("/test", false).await?;

        Ok(())
    }

    async fn test_set_owner(client: &Client) -> Result<()> {
        client
            .create("/test", WriteOptions::default())
            .await?
            .close()
            .await?;

        client
            .set_owner("/test", Some("testuser"), Some("testgroup"))
            .await?;
        let file_info = client.get_file_info("/test").await?;

        assert_eq!(file_info.owner, "testuser");
        assert_eq!(file_info.group, "testgroup");

        client.set_owner("/test", Some("testuser2"), None).await?;
        let file_info = client.get_file_info("/test").await?;

        assert_eq!(file_info.owner, "testuser2");
        assert_eq!(file_info.group, "testgroup");

        client.set_owner("/test", None, Some("testgroup2")).await?;
        let file_info = client.get_file_info("/test").await?;

        assert_eq!(file_info.owner, "testuser2");
        assert_eq!(file_info.group, "testgroup2");

        client.delete("/test", false).await?;

        Ok(())
    }

    async fn test_set_permission(client: &Client) -> Result<()> {
        client
            .create("/test", WriteOptions::default())
            .await?
            .close()
            .await?;

        let file_info = client.get_file_info("/test").await?;
        assert_eq!(file_info.permission, 0o644);

        client.set_permission("/test", 0o600).await?;
        let file_info = client.get_file_info("/test").await?;
        assert_eq!(file_info.permission, 0o600);

        client.delete("/test", false).await?;

        Ok(())
    }

    async fn test_set_replication(client: &Client) -> Result<()> {
        client
            .create("/test", WriteOptions::default())
            .await?
            .close()
            .await?;

        client.set_replication("/test", 1).await?;
        let file_info = client.get_file_info("/test").await?;
        assert_eq!(file_info.replication, Some(1));

        client.set_replication("/test", 2).await?;
        let file_info = client.get_file_info("/test").await?;
        assert_eq!(file_info.replication, Some(2));

        client.delete("/test", false).await?;

        Ok(())
    }

    async fn test_get_content_summary(client: &Client) -> Result<()> {
        let mut file1 = client.create("/test", WriteOptions::default()).await?;

        file1.write(vec![0, 1, 2, 3].into()).await?;
        file1.close().await?;

        let mut file2 = client.create("/test2", WriteOptions::default()).await?;

        file2.write(vec![0, 1, 2, 3, 4, 5].into()).await?;
        file2.close().await?;

        client.mkdirs("/testdir", 0o755, true).await?;

        let content_summary = client.get_content_summary("/").await?;
        assert_eq!(content_summary.file_count, 3,);
        assert_eq!(content_summary.directory_count, 2);
        // Test file plus the two we made above
        assert_eq!(content_summary.length, TEST_FILE_INTS as u64 * 4 + 4 + 6);

        client.delete("/test", false).await?;
        client.delete("/test2", false).await?;

        Ok(())
    }

    async fn test_acls(client: &Client) -> Result<()> {
        client
            .create("/test", WriteOptions::default())
            .await?
            .close()
            .await?;

        let acl_status = client.get_acl_status("/test").await?;

        assert!(acl_status.entries.is_empty());
        assert!(!acl_status.sticky);

        let user_entry = AclEntry::new("user", "access", "r--", Some("testuser".to_string()));

        let group_entry = AclEntry::new("group", "access", "-w-", Some("testgroup".to_string()));

        client
            .modify_acl_entries("/test", vec![user_entry.clone()])
            .await?;

        let acl_status = client.get_acl_status("/test").await?;

        // Empty group permission added automatically
        assert_eq!(acl_status.entries.len(), 2, "{:?}", acl_status.entries);
        assert!(acl_status.entries.contains(&user_entry));

        client
            .modify_acl_entries("/test", vec![group_entry.clone()])
            .await?;

        let acl_status = client.get_acl_status("/test").await?;

        // Still contains the empty group
        assert_eq!(acl_status.entries.len(), 3, "{:?}", acl_status.entries);
        assert!(acl_status.entries.contains(&user_entry));
        assert!(acl_status.entries.contains(&group_entry));

        client
            .remove_acl_entries("/test", vec![group_entry.clone()])
            .await?;

        let acl_status = client.get_acl_status("/test").await?;

        assert_eq!(acl_status.entries.len(), 2, "{:?}", acl_status.entries);
        assert!(acl_status.entries.contains(&user_entry));
        assert!(!acl_status.entries.contains(&group_entry));

        client.remove_acl("/test").await?;

        let acl_status = client.get_acl_status("/test").await?;

        assert_eq!(acl_status.entries.len(), 0);

        client.delete("/test", false).await?;

        // Default acl
        client.mkdirs("/testdir", 0o755, true).await?;

        client
            .modify_acl_entries(
                "/testdir",
                vec![AclEntry {
                    r#type: hdfs_native::acl::AclEntryType::User,
                    scope: hdfs_native::acl::AclEntryScope::Default,
                    permissions: hdfs_native::acl::FsAction::Read,
                    name: Some("testuser".to_string()),
                }],
            )
            .await?;

        let acl_status = client.get_acl_status("/testdir").await?;

        // All defaults get added automatically based on permissions
        assert_eq!(acl_status.entries.len(), 5, "{:?}", acl_status.entries);

        client
            .create("/testdir/test", WriteOptions::default())
            .await?
            .close()
            .await?;

        let acl_status = client.get_acl_status("/testdir/test").await?;

        // Default user acl added above plus the empty group permission
        assert_eq!(acl_status.entries.len(), 2, "{:?}", acl_status.entries);

        client.remove_default_acl("/testdir").await?;

        client.delete("/testdir", true).await?;

        Ok(())
    }
}
